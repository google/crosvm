// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![warn(missing_docs)]
#![recursion_limit = "128"]

//! Macros for hypervisor tests

use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::atomic::AtomicU64;

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use rand::Rng;
use syn::parse::Parse;
use syn::parse_macro_input;
use syn::Error;
use syn::Ident;
use syn::LitStr;
use syn::Token;
use syn::Visibility;

/// Embed the compiled assembly as an array.
///
/// This macro will generate a module with the given `$name` and provides a `data` function in the
/// module to allow accessing the compiled machine code as an array.
///
/// Note that this macro uses [`std::arch::global_asm`], so we can only use this macro in a global
/// scope, outside a function.
///
/// # Example
///
/// Given the following x86 assembly:
/// ```Text
/// 0:  01 d8                   add    eax,ebx
/// 2:  f4                      hlt
/// ```
///
/// ```rust
/// # use hypervisor_test_macro::global_asm_data;
/// global_asm_data!(
///     my_code,
///     ".code64",
///     "add eax, ebx",
///     "hlt",
/// );
/// # fn main() {
/// assert_eq!([0x01, 0xd8, 0xf4], my_code::data());
/// # }
/// ```
///
/// It is supported to pass arbitrary supported [`std::arch::global_asm`] operands and options.
/// ```rust
/// # use hypervisor_test_macro::global_asm_data;
/// fn f() {}
/// global_asm_data!(
///     my_code1,
///     ".global {0}",
///     ".code64",
///     "add eax, ebx",
///     "hlt",
///     sym f,
/// );
/// global_asm_data!(
///     my_code2,
///     ".code64",
///     "add eax, ebx",
///     "hlt",
///     options(raw),
/// );
/// # fn main() {
/// assert_eq!([0x01, 0xd8, 0xf4], my_code1::data());
/// assert_eq!([0x01, 0xd8, 0xf4], my_code2::data());
/// # }
/// ```
///
/// It is also supported to specify the visibility of the generated module. Note that the below
/// example won't work if the `pub` in the macro is missing.
/// ```rust
/// # use hypervisor_test_macro::global_asm_data;
/// mod my_mod {
///     // This use is needed to import the global_asm_data macro to this module.
///     use super::*;
///
///     global_asm_data!(
///         // pub is needed so that my_mod::my_code is visible to the outer scope.
///         pub my_code,
///         ".code64",
///         "add eax, ebx",
///         "hlt",
///     );
/// }
/// # fn main() {
/// assert_eq!([0x01, 0xd8, 0xf4], my_mod::my_code::data());
/// # }
/// ```
#[proc_macro]
pub fn global_asm_data(item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(item as GlobalAsmDataArgs);
    global_asm_data_impl(args).unwrap_or_else(|e| e.to_compile_error().into())
}

struct GlobalAsmDataArgs {
    visibility: Visibility,
    mod_name: Ident,
    global_asm_strings: Vec<LitStr>,
    global_asm_rest_args: TokenStream2,
}

impl Parse for GlobalAsmDataArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        // The first argument is visibilty + identifier, e.g. my_code or pub my_code. The identifier
        // will be used as the name of the gnerated module.
        let visibility: Visibility = input.parse()?;
        let mod_name: Ident = input.parse()?;
        // There must be following arguments, so we consume the first argument separator here.
        input.parse::<Token![,]>()?;

        // Retrieve the input assemblies, which are a list of comma separated string literals. We
        // need to obtain the list of assemblies explicitly, so that we can insert the begin tag and
        // the end tag to the global_asm! call when we generate the result code.
        let mut global_asm_strings = vec![];
        loop {
            let lookahead = input.lookahead1();
            if !lookahead.peek(LitStr) {
                // If the upcoming tokens are not string literal, we hit the end of the input
                // assemblies.
                break;
            }
            global_asm_strings.push(input.parse::<LitStr>()?);

            if input.is_empty() {
                // In case the current string literal is the last argument.
                break;
            }
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                // In case the current string literal is the last argument with a trailing comma.
                break;
            }
        }

        // We store the rest of the arguments, and we will forward them as is to global_asm!.
        let global_asm_rest_args: TokenStream2 = input.parse()?;
        Ok(Self {
            visibility,
            mod_name,
            global_asm_strings,
            global_asm_rest_args,
        })
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn global_asm_data_impl(
    GlobalAsmDataArgs {
        visibility,
        mod_name,
        global_asm_strings,
        global_asm_rest_args,
    }: GlobalAsmDataArgs,
) -> Result<TokenStream, Error> {
    let span = Span::call_site();

    // Generate the unique tags based on the macro input, code location and a random number to avoid
    // symbol collision.
    let tag_base_name = {
        let content_id = {
            let mut hasher = DefaultHasher::new();
            span.source_text().hash(&mut hasher);
            hasher.finish()
        };
        let location_id = format!(
            "{}_{}_{}_{}",
            span.start().line,
            span.start().column,
            span.end().line,
            span.end().column
        );
        let rand_id = rand::thread_rng().gen::<u64>();
        let static_counter_id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let prefix = "crosvm_hypervisor_test_macro_global_asm_data";
        format!(
            "{}_{}_{}_{}_{}_{}",
            prefix, mod_name, content_id, location_id, static_counter_id, rand_id
        )
    };
    let start_tag = format!("{}_start", tag_base_name);
    let end_tag = format!("{}_end", tag_base_name);

    let global_directive = LitStr::new(&format!(".global {}, {}", start_tag, end_tag), span);
    let start_tag_asm = LitStr::new(&format!("{}:", start_tag), span);
    let end_tag_asm = LitStr::new(&format!("{}:", end_tag), span);
    let start_tag_ident = Ident::new(&start_tag, span);
    let end_tag_ident = Ident::new(&end_tag, span);

    Ok(quote! {
        #visibility mod #mod_name {
            use super::*;

            extern {
                static #start_tag_ident: u8;
                static #end_tag_ident: u8;
            }

            std::arch::global_asm!(
                #global_directive,
                #start_tag_asm,
                #(#global_asm_strings),*,
                #end_tag_asm,
                #global_asm_rest_args
            );
            pub fn data() -> &'static [u8] {
                // SAFETY:
                // * The extern statics are u8, and any arbitrary bit patterns are valid for u8.
                // * The data starting from start to end is valid u8.
                // * Without unsafe block, one can't mutate the value between start and end. In
                //   addition, it is likely that the data is written to a readonly block, and can't
                //   be mutated at all.
                // * The address shouldn't be too large, and won't wrap around.
                unsafe {
                    let ptr = std::ptr::addr_of!(#start_tag_ident);
                    let len = std::ptr::addr_of!(#end_tag_ident).offset_from(ptr);
                    std::slice::from_raw_parts(
                        ptr,
                        len.try_into().expect("length must be positive")
                    )
                }
            }
        }
    }
    .into())
}
