use darling::{FromField, FromVariant};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

use common::str::convert::{CapitalizedString, Case};

#[derive(FromVariant)]
#[darling(attributes(command))]
struct VOpts {
    name: Option<String>,
}

#[derive(FromField)]
#[darling(attributes(command))]
struct FOpts {
    name: Option<String>,
    display_with: Option<syn::Expr>,
    defaults: Option<syn::Expr>,
    defaults_str: Option<syn::Lit>,
    ignore: Option<()>,
}

#[proc_macro_derive(Command, attributes(command))]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput {
        ident,
        generics,
        data,
        ..
    } = parse_macro_input!(input);

    let match_variants = match data {
        syn::Data::Enum(data) => {
            let tokens: TokenStream2 = data.variants.iter().map(match_enum_variant).collect();
            quote! {
                match self {
                    #tokens
                }
            }
        }
        syn::Data::Struct(_) | syn::Data::Union(_) => {
            unimplemented!("currently only supporting Enums")
        }
    };

    quote! {
        impl #generics std::fmt::Display for #ident #generics {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                #match_variants
            }
        }
    }
    .into()
}

fn match_enum_variant(variant: &syn::Variant) -> TokenStream2 {
    let name = VOpts::from_variant(variant).expect("wrong Options").name;
    let variant_name = format!("{}:", name.unwrap_or_else(|| variant.ident.to_string()));
    let variant_ident = &variant.ident;
    let fields = variant
        .fields
        .iter()
        .map(|f| f.ident.as_ref())
        .collect::<Option<Vec<_>>>()
        .expect("only support for named structs");
    if fields.is_empty() {
        quote!(#variant_ident => write!(f, #variant_name),)
    } else {
        let push_fields: TokenStream2 = variant.fields.iter().map(match_field).collect();
        quote! {
            #variant_ident{#(#fields),*} => {
                write!(f, #variant_name)?;
                #push_fields
                Ok(())
            },
        }
    }
}

fn match_field(field: &syn::Field) -> TokenStream2 {
    let opts = FOpts::from_field(field).expect("wrong Options");
    if let Some(()) = opts.ignore {
        return quote!();
    }
    let ident = field.ident.as_ref().expect("no Tuple structs");
    let name = opts.name.unwrap_or_else(|| {
        CapitalizedString::new_into(ident.to_string().as_ref(), Case::Pascal)
            .unwrap()
            .to_string()
    });

    let ident_map = opts.display_with.map_or(quote!(#ident), |map| quote!(#map));
    let push = quote!(push(f, #name, #ident_map)?;);

    let default = match (opts.defaults, opts.defaults_str) {
        (None, None) => None,
        (Some(expr), None) => Some(quote!(#expr)),
        (None, Some(lit)) => Some(quote!(#lit)),
        (Some(_), Some(_)) => panic!("only one default allowed"),
    };

    match (default, extract_type_from_option(&field.ty)) {
        (None, None) => push,
        (None, Some(_)) => quote!(if let Some(#ident) = #ident { #push }),
        (Some(default), None) => quote!(if #ident != &#default { #push }),
        (Some(default), Some(_)) => quote! {
            if let Some(#ident) = #ident.filter(|it| it != &#default) { #push }
        },
    }
}

fn extract_type_from_option(ty: &syn::Type) -> Option<&syn::Type> {
    // If it is not `TypePath`, it is not possible to be `Option<T>`, return `None`
    if let syn::Type::Path(syn::TypePath { qself: None, path }) = ty {
        // We have limited the 5 ways to write `Option`, and we can see that after `Option`,
        // there will be no `PathSegment` of the same level
        // Therefore, we only need to take out the highest level `PathSegment` and splice it into a string
        // for comparison with the analysis result
        let segments_str = &path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join(":");
        // Concatenate `PathSegment` into a string, compare and take out the `PathSegment` where `Option` is located
        let option_segment = ["Option", "std:option:Option", "core:option:Option"]
            .iter()
            .find(|s| segments_str == *s)
            .and_then(|_| path.segments.last());
        let inner_type = option_segment
            // Take out the generic parameters of the `PathSegment` where `Option` is located
            // If it is not generic, it is not possible to be `Option<T>`, return `None`
            // But this situation may not occur
            .and_then(|path_seg| match &path_seg.arguments {
                syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
                    args,
                    ..
                }) => args.first(),
                _ => None,
            })
            // Take out the type information in the generic parameter
            // If it is not a type, it is not possible to be `Option<T>`, return `None`
            // But this situation may not occur
            .and_then(|generic_arg| match generic_arg {
                syn::GenericArgument::Type(ty) => Some(ty),
                _ => None,
            });
        // Return `T` in `Option<T>`
        return inner_type;
    }
    None
}
