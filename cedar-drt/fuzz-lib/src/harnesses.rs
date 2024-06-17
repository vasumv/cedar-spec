use arbitrary::{Arbitrary, Unstructured};
use cedar_drt::*;

use cedar_policy_core::ast;
use cedar_policy_core::entities::Entities;
use cedar_policy_generators::{
    abac::{ABACPolicy, ABACRequest},
    err::Error,
    hierarchy::HierarchyGenerator,
    schema::Schema,
    settings::ABACSettings,
};
use fuzz_inputs::{abac_type_directed::ABACTypeDirectedFuzzTargetInput, rbac::{PolicyGroup, RBACFuzzTargetInput}};
use fuzz_inputs::eval_type_directed::EvalTypeDirectedFuzzTargetInput;
use log::{debug, info};
use serde::Serialize;
use serde_json::json;
use std::io::Write;
use std::{convert::TryFrom, path::Path, time::SystemTime};

use crate::*;

pub fn test_abac_type_directed(input: &ABACTypeDirectedFuzzTargetInput, valid: bool) {
    initialize_log();
    let mut obs_out = TycheTest::default(); 
    if (valid) {
        let exec_start_time = SystemTime::now();
        obs_out = input.to_tyche();
        let def_impl = LeanDefinitionalEngine::new();
        let mut policyset = ast::PolicySet::new();
        let policy: ast::StaticPolicy = input.policy.clone().into();
        policyset.add_static(policy.clone()).unwrap();
        debug!("Schema: {}\n", input.schema.schemafile_string());
        debug!("Policies: {policyset}\n");
        debug!("Entities: {}\n", input.entities);

        obs_out.status = "gave_up".to_string();
        if let Ok(schema) = ValidatorSchema::try_from(input.schema.clone()) {
            let validator = Validator::new(schema);
            let validation_result = validator.validate(&policyset, ValidationMode::default());
            if validation_result.validation_passed() {
                obs_out.status = "passed".to_string();
                obs_out.status_reason = "validator_passed".to_string();
                obs_out.features["validation_errors"] = json!(0);
            } else {
                // Set the obs_out status reason to be a vector (validation_errors) that are mapped to its kind.
                obs_out.status = "gave_up".to_string();
                let validation_errors = validation_result
                    .validation_errors()
                    .into_iter()
                    .map(|e| e.kind().to_string())
                    .collect::<Vec<_>>();
                obs_out.features["validation_errors"] = json!(validation_errors.len());
                obs_out.status_reason = validation_errors.join(", ");
            }
        }

        let requests = input
            .requests
            .clone()
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();

        let mut total_auth_errors = 0;
        for request in requests.iter().cloned() {
            debug!("Request : {request}");
            let (rust_res, total_dur) =
                time_function(|| run_auth_test(&def_impl, request, &policyset, &input.entities));

            info!("{}{}", TOTAL_MSG, total_dur.as_nanos());

            total_auth_errors += rust_res.diagnostics.errors.len();
            // additional invariant:
            // type-directed fuzzing should never produce wrong-number-of-arguments errors
            assert_eq!(
                rust_res
                    .diagnostics
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .filter(|err| err.contains("wrong number of arguments"))
                    .collect::<Vec<String>>(),
                Vec::<String>::new()
            );
        }
        let duration_since_gen = SystemTime::now()
            .duration_since(exec_start_time)
            .expect("Time went backwards");
        obs_out.features["total_auth_errors"] = json!(total_auth_errors);
        obs_out.timing["generate"] = json!(input.gen_time);
        obs_out.timing["execute"] = json!(
            duration_since_gen.as_secs_f64()
                + duration_since_gen.subsec_nanos() as f64 / 1_000_000_000.0
        );
    } else {
        obs_out.status = "gave_up".to_string();
        obs_out.status_reason = "arbitrary generation failed".to_string();
    }
    if let Ok(_) = std::env::var("DRT_OBSERVABILITY") {
        let test_name = std::env::var("FUZZ_TARGET").unwrap_or("fuzz-target".to_string());

        // obs_out.features = input.get_features();
        // Make a directory called tyche-out/ in the current directory
        let tyche_out = Path::new("fuzz/observations");
        std::fs::create_dir_all(tyche_out).expect("Error creating tyche-out directory");

        // Make a file in tyche-out with the name of the test followed by _testcases.jsonl
        let tyche_file_path = tyche_out.join(format!("{}_testcases.jsonl", test_name));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tyche_file_path)
            .unwrap();
        let obs_out_json = serde_json::to_value(&obs_out).unwrap();
        writeln!(file, "{}", obs_out_json).expect("Error writing to tyche file");
    }
}

pub fn test_eval_type_directed(input: Result<EvalTypeDirectedFuzzTargetInput, arbitrary::Error>) {
    initialize_log();
    let mut obs_out = TycheTest::default();
    if let Ok(input) = input {
        obs_out = input.to_tyche();
        let def_impl = LeanDefinitionalEngine::new();
        debug!("Schema: {}\n", input.schema.schemafile_string());
        debug!("expr: {}\n", input.expression);
        debug!("Entities: {}\n", input.entities);
        run_eval_test(
            &def_impl,
            input.request.into(),
            &input.expression,
            &input.entities,
            true,
        )
    } else {
        obs_out.status = "gave_up".to_string();
        obs_out.status_reason = "arbitrary generation failed".to_string();
    }
    if let Ok(_) = std::env::var("DRT_OBSERVABILITY") {
        let test_name = std::env::var("FUZZ_TARGET").unwrap_or("eval-type-directed".to_string());

        // Make a directory called tyche-out/ in the current directory
        let tyche_out = Path::new("fuzz/observations");
        std::fs::create_dir_all(tyche_out).expect("Error creating tyche-out directory");

        // Make a file in tyche-out with the name of the test followed by _testcases.jsonl
        let tyche_file_path = tyche_out.join(format!("{}_testcases.jsonl", test_name));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tyche_file_path)
            .unwrap();
        let obs_out_json = serde_json::to_value(&obs_out).unwrap();
        writeln!(file, "{}", obs_out_json).expect("Error writing to tyche file");
    }
}

pub fn test_rbac(input: &RBACFuzzTargetInput) {
    initialize_log();
    let def_impl = LeanDefinitionalEngine::new();
    let obs_out = input.to_tyche();
    if let Ok(entities) = Entities::try_from(input.hierarchy.clone()) {
        let mut policyset = ast::PolicySet::new();
        for pg in input.policy_groups.clone() {
            match pg {
                PolicyGroup::StaticPolicy(p) => {
                    p.0.add_to_policyset(&mut policyset);
                }
                PolicyGroup::TemplateWithLinks { template, links } => {
                    template.0.add_to_policyset(&mut policyset);
                    for link in links {
                        link.add_to_policyset(&mut policyset);
                    }
                }
            };
        }
        for rbac_request in input.requests.clone().into_iter() {
            let request = ast::Request::from(rbac_request);
            let (_, dur) =
                time_function(|| run_auth_test(&def_impl, request, &policyset, &entities));
            info!("{}{}", TOTAL_MSG, dur.as_nanos());
        }
    }
    if let Ok(_) = std::env::var("DRT_OBSERVABILITY") {
        let test_name = std::env::var("FUZZ_TARGET").unwrap_or("fuzz-target".to_string());

        // obs_out.features = input.get_features();
        // Make a directory called tyche-out/ in the current directory
        let tyche_out = Path::new("fuzz/observations");
        std::fs::create_dir_all(tyche_out).expect("Error creating tyche-out directory");

        // Make a file in tyche-out with the name of the test followed by _testcases.jsonl
        let tyche_file_path = tyche_out.join(format!("{}_testcases.jsonl", test_name));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tyche_file_path)
            .unwrap();
        let obs_out_json = serde_json::to_value(&obs_out).unwrap();
        writeln!(file, "{}", obs_out_json).expect("Error writing to tyche file");
    }
}