// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod tokenized {
    use Tokenized;
    use Tokenized::*;

    #[test]
    fn enum_() {
        assert_eq!(Tokenized::from_str("enum"), Enum);
    }

    #[test]
    fn visibility() {
        assert_eq!(Tokenized::from_str("pub"), Visiblity);
        assert_eq!(Tokenized::from_str("pub(crate)"), Visiblity);
        assert_eq!(Tokenized::from_str("pub(my_module)"), Visiblity);
        assert_eq!(Tokenized::from_str("pub( crate )"), Visiblity);
    }

    #[test]
    fn ident() {
        assert_eq!(Tokenized::from_str("Important"),
                   Ident("Important".to_owned()));
        assert_eq!(Tokenized::from_str("hello,"), Ident("hello".to_owned()));
        assert_eq!(Tokenized::from_str("world2"), Ident("world2".to_owned()));
        assert_eq!(Tokenized::from_str("A,"), Ident("A".to_owned()));
    }


    #[test]
    fn field_ident() {
        assert_eq!(Tokenized::from_str("index:"),
                   FieldIdent("index".to_owned()));
        assert_eq!(Tokenized::from_str("a:"), FieldIdent("a".to_owned()));
    }

    #[test]
    fn ident_and_type() {
        assert_eq!(Tokenized::from_str("a(u32)"),
                   IdentAndType("a".to_owned(), "u32".to_owned()));
        assert_eq!(Tokenized::from_str("Socket(usize),"),
                   IdentAndType("Socket".to_owned(), "usize".to_owned()));
    }

    #[test]
    fn open_brace() {
        assert_eq!(Tokenized::from_str("{"), OpenBrace);
    }

    #[test]
    fn close_brace() {
        assert_eq!(Tokenized::from_str("}"), CloseBrace);
        assert_eq!(Tokenized::from_str("},"), CloseBrace);
    }

    #[test]
    #[should_panic]
    fn empty() {
        Tokenized::from_str("");
    }
}

mod parse_state {
    use {Tokenized, States, ParseState, EnumModel, EnumVariant, EnumVariantData};
    use Tokenized::*;

    fn parse_tokens(tokens: &[Tokenized]) -> EnumModel {
        let mut state = ParseState::new();
        for token in tokens {
            state.handle_token(token.clone());
        }
        assert_eq!(state.current_state,
                   States::End,
                   "unexpected end after parsing source enum");
        state.model
    }

    #[test]
    fn empty_struct() {
        let model = parse_tokens(&[Visiblity,
                                   Enum,
                                   Ident("Blarg".to_owned()),
                                   OpenBrace,
                                   CloseBrace]);
        let expected = EnumModel {
            name: "Blarg".to_string(),
            variants: Vec::new(),
        };
        assert_eq!(model, expected);
    }

    #[test]
    #[should_panic]
    fn invalid_token() {
        parse_tokens(&[Visiblity,
                       Enum,
                       Ident("Blarg".to_owned()),
                       OpenBrace,
                       CloseBrace,
                       CloseBrace]);
    }

    #[test]
    fn only_unit_variants() {
        let model = parse_tokens(&[Enum,
                                   Ident("Foo".to_owned()),
                                   OpenBrace,
                                   Ident("A".to_owned()),
                                   Ident("B".to_owned()),
                                   Ident("C".to_owned()),
                                   CloseBrace]);
        let expected = EnumModel {
            name: "Foo".to_string(),
            variants: vec![EnumVariant {
                               name: "A".to_owned(),
                               data: None,
                           },
                           EnumVariant {
                               name: "B".to_owned(),
                               data: None,
                           },
                           EnumVariant {
                               name: "C".to_owned(),
                               data: None,
                           }],
        };
        assert_eq!(model, expected);
    }

    #[test]
    fn unnamed_data() {
        let model = parse_tokens(&[Enum,
                                   Ident("Foo".to_owned()),
                                   OpenBrace,
                                   IdentAndType("A".to_owned(), "u32".to_owned()),
                                   Ident("B".to_owned()),
                                   IdentAndType("C".to_owned(), "usize".to_owned()),
                                   CloseBrace]);
        let expected = EnumModel {
            name: "Foo".to_string(),
            variants: vec![EnumVariant {
                               name: "A".to_owned(),
                               data: Some(EnumVariantData {
                                              name: None,
                                              type_: "u32".to_owned(),
                                          }),
                           },
                           EnumVariant {
                               name: "B".to_owned(),
                               data: None,
                           },
                           EnumVariant {
                               name: "C".to_owned(),
                               data: Some(EnumVariantData {
                                              name: None,
                                              type_: "usize".to_owned(),
                                          }),
                           }],
        };
        assert_eq!(model, expected);
    }

    #[test]
    fn named_data() {
        let model = parse_tokens(&[Enum,
                                   Ident("Foo".to_owned()),
                                   OpenBrace,
                                   Ident("A".to_owned()),
                                   OpenBrace,
                                   FieldIdent("index".to_owned()),
                                   Ident("u16".to_owned()),
                                   CloseBrace,
                                   CloseBrace]);
        let expected = EnumModel {
            name: "Foo".to_string(),
            variants: vec![EnumVariant {
                               name: "A".to_owned(),
                               data: Some(EnumVariantData {
                                              name: Some("index".to_owned()),
                                              type_: "u16".to_owned(),
                                          }),
                           }],
        };
        assert_eq!(model, expected);
    }
}

mod enum_model {
    use {EnumModel, EnumVariant};

    #[test]
    fn variant_bits() {
        let mut model = EnumModel {
            name: "Baz".to_string(),
            variants: vec![EnumVariant {
                               name: "A".to_owned(),
                               data: None,
                           }],
        };
        assert_eq!(model.variant_bits(), 0);

        model.variants.append(
            &mut vec![
                EnumVariant {
                    name: "B".to_owned(),
                    data: None,
                },
                EnumVariant {
                    name: "C".to_owned(),
                    data: None,
                }
            ]
        );
        assert_eq!(model.variant_bits(), 2);
        for _ in 0..1021 {
            model
                .variants
                .push(EnumVariant {
                          name: "Dynamic".to_owned(),
                          data: None,
                      });
        }
        assert_eq!(model.variant_bits(), 10);
        model
            .variants
            .push(EnumVariant {
                      name: "OneMore".to_owned(),
                      data: None,
                  });
        assert_eq!(model.variant_bits(), 11);
    }
}

#[test]
fn poll_token_e2e() {
    let input = "enum Token { A, B, C, D(usize), E { foobaz: u32 }, }";
    let output = ::poll_token_inner(input);
    let expected = "impl PollToken for Token {
    fn as_raw_token(&self) -> u64 {
match *self {
Token::A => 0,
Token::B => 1,
Token::C => 2,
Token::D(data) => 3 | ((data as u64) << 3),
Token::E{ foobaz: data } => 4 | ((data as u64) << 3),
}
    }

    fn from_raw_token(data: u64) -> Self {
match data & 0x07 {
0 => Token::A,
1 => Token::B,
2 => Token::C,
3 => Token::D((data >> 3) as usize),
4 => Token::E{ foobaz: (data >> 3) as u32 },
_ => unreachable!()
}
    }
}";
    assert_eq!(output.as_str(), expected);
}
