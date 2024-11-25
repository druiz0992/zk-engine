use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_str, punctuated::Punctuated, Generics, ItemFn, ItemImpl, ItemStruct, ItemTrait,
    WherePredicate,
};

fn add_bounds_to_generics(generics: &mut Generics, bounds: &[WherePredicate]) {
    generics.make_where_clause();

    // Retain both type and constant generics
    let mut new_params = Punctuated::new();

    for param in generics.params.iter() {
        // Retain all generic parameters including constants
        new_params.push(param.clone());
    }

    generics.params = new_params;

    if let Some(where_clause) = generics.where_clause.as_mut() {
        where_clause.predicates.extend(bounds.iter().cloned());
    }
}

#[proc_macro_attribute]
pub fn client_bounds(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = item.clone();

    // Define each bound as a `WherePredicate`
    let bounds: Vec<WherePredicate> = vec![
        parse_str("P: SWCurveConfig").unwrap(),
        parse_str("<P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = <V as Pairing>::ScalarField>").unwrap(),
        parse_str("V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = P::BaseField>").unwrap(),
        parse_str("<V as Pairing>::BaseField: RescueParameter + SWToTEConParam + PoseidonParams<Field = V::BaseField>").unwrap(),
        parse_str("<V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>").unwrap(),
        parse_str("VSW: SWCurveConfig<BaseField = <V as Pairing>::BaseField, ScalarField = <V as Pairing>::ScalarField>").unwrap(),
    ];
    //<V as Pairing>::BaseField: PrimeField + PoseidonParams<Field = V::BaseField>,

    // Parse the item and handle based on its type
    if let Ok(mut struct_item) = syn::parse::<ItemStruct>(item.clone()) {
        // Check if it's a tuple struct by inspecting unnamed fields
        add_bounds_to_generics(&mut struct_item.generics, &bounds);

        let expanded = quote! {
            #struct_item
        };
        return expanded.into();
    } else if let Ok(mut impl_item) = syn::parse::<ItemImpl>(item.clone()) {
        // Attach where bounds to the impl block
        add_bounds_to_generics(&mut impl_item.generics, &bounds);

        let expanded = quote! {
            #impl_item
        };
        return expanded.into();
    } else if let Ok(mut fn_item) = syn::parse::<ItemFn>(item.clone()) {
        // Attach where bounds to the function
        add_bounds_to_generics(&mut fn_item.sig.generics, &bounds);

        let expanded = quote! {
            #fn_item
        };
        return expanded.into();
    } else if let Ok(mut trait_item) = syn::parse::<ItemTrait>(item.clone()) {
        // Attach where bounds to the function
        add_bounds_to_generics(&mut trait_item.generics, &bounds);

        let expanded = quote! {
            #trait_item
        };
        return expanded.into();
    }

    // Return an error if the item is not supported
    panic!("Expected a struct, trait,  impl block, or function.");
}

#[proc_macro_attribute]
pub fn sequencer_bounds(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = item.clone();
    // Define each bound as a `WherePredicate`
    let bounds: Vec<WherePredicate> = vec![
        parse_str("V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>>").unwrap(),
        parse_str("<<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>").unwrap(),
        parse_str("<V as Pairing>::BaseField: PrimeField + PoseidonParams<Field = P::ScalarField> + RescueParameter + SWToTEConParam").unwrap(),
        parse_str("<V as Pairing>::ScalarField: PrimeField + PoseidonParams<Field = P::BaseField> + RescueParameter + SWToTEConParam").unwrap(),
        parse_str("P: Pairing<BaseField = V::ScalarField, ScalarField = V::BaseField>").unwrap(),
        parse_str("P: Pairing<G1Affine = Affine<SW>, G1 = Projective<SW>>").unwrap(),
        parse_str("V: Pairing").unwrap(),
        parse_str("<<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>").unwrap(),
        parse_str("SW: SWCurveConfig<BaseField = V::ScalarField, ScalarField = V::BaseField>").unwrap(),
        parse_str("VSW: SWCurveConfig<BaseField = V::BaseField, ScalarField = V::ScalarField>").unwrap(),
    ];

    // Parse the item and handle based on its type
    if let Ok(mut struct_item) = syn::parse::<ItemStruct>(item.clone()) {
        // Check if it's a tuple struct by inspecting unnamed fields
        add_bounds_to_generics(&mut struct_item.generics, &bounds);

        let expanded = quote! {
            #struct_item
        };
        return expanded.into();
    } else if let Ok(mut impl_item) = syn::parse::<ItemImpl>(item.clone()) {
        // Attach where bounds to the impl block
        add_bounds_to_generics(&mut impl_item.generics, &bounds);

        let expanded = quote! {
            #impl_item
        };
        return expanded.into();
    } else if let Ok(mut fn_item) = syn::parse::<ItemFn>(item.clone()) {
        // Attach where bounds to the function
        add_bounds_to_generics(&mut fn_item.sig.generics, &bounds);

        let expanded = quote! {
            #fn_item
        };
        return expanded.into();
    } else if let Ok(mut trait_item) = syn::parse::<ItemTrait>(item.clone()) {
        // Attach where bounds to the function
        add_bounds_to_generics(&mut trait_item.generics, &bounds);

        let expanded = quote! {
            #trait_item
        };
        return expanded.into();
    }

    // Return an error if the item is not supported
    panic!("Expected a struct, trait,  impl block, or function.");
}

#[proc_macro_attribute]
pub fn prover_bounds(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = item.clone();
    // Define each bound as a `WherePredicate`
    let bounds: Vec<WherePredicate> = vec![
        parse_str("V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = <P as CurveConfig>::BaseField>").unwrap(),
        parse_str("<V as Pairing>::BaseField: PrimeField + PoseidonParams<Field = <P as Pairing>::ScalarField> + RescueParameter + SWToTEConParam").unwrap(),
        parse_str("<V as Pairing>::ScalarField: PrimeField + PoseidonParams<Field = <P as Pairing>::BaseField> + RescueParameter + SWToTEConParam").unwrap(),
        parse_str("<V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>").unwrap(),
        parse_str("P: Pairing<G1Affine = Affine<SW>, G1 = Projective<SW>> + SWCurveConfig + Pairing<BaseField = <V as Pairing>::ScalarField, ScalarField = <V as Pairing>::BaseField>").unwrap(),
        parse_str("<P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>").unwrap(), 
        parse_str("SW: SWCurveConfig<BaseField = <V as Pairing>::ScalarField, ScalarField = <V as Pairing>::BaseField>").unwrap(),
        parse_str("VSW: SWCurveConfig<BaseField = <V as Pairing>::BaseField, ScalarField = <V as Pairing>::ScalarField>").unwrap(),
    ];

    // Parse the item and handle based on its type
    if let Ok(mut struct_item) = syn::parse::<ItemStruct>(item.clone()) {
        // Check if it's a tuple struct by inspecting unnamed fields
        add_bounds_to_generics(&mut struct_item.generics, &bounds);

        let expanded = quote! {
            #struct_item
        };
        return expanded.into();
    } else if let Ok(mut impl_item) = syn::parse::<ItemImpl>(item.clone()) {
        // Attach where bounds to the impl block
        add_bounds_to_generics(&mut impl_item.generics, &bounds);

        let expanded = quote! {
            #impl_item
        };
        return expanded.into();
    } else if let Ok(mut fn_item) = syn::parse::<ItemFn>(item.clone()) {
        // Attach where bounds to the function
        add_bounds_to_generics(&mut fn_item.sig.generics, &bounds);

        let expanded = quote! {
            #fn_item
        };
        return expanded.into();
    } else if let Ok(mut trait_item) = syn::parse::<ItemTrait>(item.clone()) {
        // Attach where bounds to the function
        add_bounds_to_generics(&mut trait_item.generics, &bounds);

        let expanded = quote! {
            #trait_item
        };
        return expanded.into();
    }

    // Return an error if the item is not supported
    panic!("Expected a struct, trait,  impl block, or function.");
}
