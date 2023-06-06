use proc_macro::TokenStream;
use quote::quote;
use syn::{self, Field};


#[proc_macro_derive(CanonicalFlatten)]
pub fn canonical_flatten_derive(input: TokenStream) -> TokenStream {
    // Construct a representation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    impl_canonical_flatten(&ast)
}

fn impl_canonical_flatten(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let mut flat_fields: Vec<syn::Ident> = Vec::new();
    let mut nested_fields: Vec<syn::Ident> = Vec::new();
    if let syn::Data::Struct(data) = &ast.data {
        if let syn::Fields::Named(f) = &data.fields {
            for field in f.named.clone() {
                let (ident,flat) = parse_field(field);
                if flat {
                    flat_fields.push(ident);
                } else {
                    nested_fields.push(ident);
                }
            }
        }
    }
    let field_names: Vec<String> = flat_fields.clone().into_iter().map(|ident| ident.to_string()).collect();
    let gen = quote! {
        impl CanonicalFlatten for #name {
            fn flatten(&self) -> Vec<String> {
                let mut v = Vec::new();
                #(
                    v.push(#field_names.to_owned() + ":" + &format!("{:?}",&self.#flat_fields));
                )*
                #(
                    v.append(&mut (self.#nested_fields.flatten()));
                )*
                v
            }
        }
    };
    gen.into()
}

fn parse_field(field: Field) -> (syn::Ident, bool) {
    if let syn::Type::Path(path) = field.ty.clone() {
        match path.path.segments[0].ident.to_string().as_str() {
            "String" => (field.ident.clone().unwrap(),true),
            "Vec" => (field.ident.clone().unwrap(),true),
            _ => (field.ident.clone().unwrap(),false)
        }
    } else {
        panic!("TODO! Handle non-path types")
    }
}
