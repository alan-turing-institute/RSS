use proc_macro2::TokenStream as TokenStream2;
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
    let mut tokens: Vec<TokenStream2> = Vec::new();
    
    if let syn::Data::Struct(data) = &ast.data {
        if let syn::Fields::Named(f) = &data.fields {
            for field in f.named.clone() {
                tokens.push(tokenise(parse_field(field)));
            }
        }
    }
    let gen = quote! {
        impl CanonicalFlatten for #name {
            fn flatten(&self) -> Vec<String> {
                let mut v = Vec::new();
                #( #tokens )*
                v
            }
        }
    };
    gen.into()
}

fn parse_field(field: Field) -> ParsedField {
    let ident = field.ident.unwrap();
    if let syn::Type::Path(path) = field.ty.clone() {
        match path.path.segments[0].ident.to_string().as_str() {
            "String" => ParsedField::String((ident.clone(),ident.to_string())),
            "Vec" => ParsedField::Vec((ident.clone(),ident.to_string())),
            _ => ParsedField::Nested((ident.clone(),ident.to_string()))
        }
    } else {
        panic!("TODO! Handle non-path types")
    }
}

enum ParsedField {
    String((syn::Ident,String)),
    Vec((syn::Ident,String)),
    Nested((syn::Ident,String))
}

fn tokenise(field: ParsedField) -> TokenStream2 {
    match field {
        ParsedField::String((ident,name)) => {
            quote! { v.push(#name.to_owned() + ":" + &self.#ident); }
        },
        ParsedField::Vec((ident,name)) => {
            quote! { v.push(#name.to_owned() + ":" + &format!("{:?}",&self.#ident)); }
        },
        ParsedField::Nested((ident,_)) => {
            quote! { v.append(&mut (self.#ident.flatten())); }
        }
    }
}
