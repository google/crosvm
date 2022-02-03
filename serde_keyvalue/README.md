# Serde deserializer from key=value strings

A lightweight serde deserializer for strings containing key-value pairs separated by commas, as
commonly found in command-line parameters.

Say your program takes a command-line option of the form:

```text
--foo type=bar,active,nb_threads=8
```

This crate provides a `from_key_values` function that deserializes these key-values into a
configuration structure. Since it uses serde, the same configuration structure can also be created
from any other supported source (such as a TOML or YAML configuration file) that uses the same keys.

Integration with the [argh](https://github.com/google/argh) command-line parser is also provided via
the `argh_derive` feature.

See the inline documentation for examples and more details.
