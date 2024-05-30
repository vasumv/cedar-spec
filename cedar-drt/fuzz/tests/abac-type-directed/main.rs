/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![no_main]
use cedar_drt::*;
use cedar_drt_inner::{
    drop_some_entities, run_auth_test, time_function, TycheFormat, TycheTest, Validator,
};
use cedar_policy_core::ast;
use cedar_policy_core::entities::Entities;
use cedar_policy_generators::{
    abac::{ABACPolicy, ABACRequest},
    err::Error,
    hierarchy::HierarchyGenerator,
    schema::Schema,
    settings::ABACSettings,
};
use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use log::{debug, info};
use serde::Serialize;
use serde_json::json;
use std::io::Write;
use std::{convert::TryFrom, path::Path, time::SystemTime};

/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 8 associated requests
#[derive(Debug, Clone, Serialize)]
pub struct FuzzTargetInput {
    /// generated schema
    #[serde(skip)]
    pub schema: Schema,
    /// generated entity slice
    #[serde(skip)]
    pub entities: Entities,
    /// generated policy
    pub policy: ABACPolicy,
    /// the requests to try for this hierarchy and policy. We try 8 requests per
    /// policy/hierarchy
    #[serde(skip)]
    pub requests: [ABACRequest; 8],
    gen_time: f64,
}

/// settings for this fuzz target
const SETTINGS: ABACSettings = ABACSettings {
    match_types: true,
    enable_extensions: true,
    max_depth: 3,
    max_width: 3,
    enable_additional_attributes: false,
    enable_like: true,
    enable_action_groups_and_attrs: true,
    enable_arbitrary_func_call: true,
    enable_unknowns: false,
    enable_action_in_constraints: true,
    enable_unspecified_apply_spec: true,
};

impl<'a> Arbitrary<'a> for FuzzTargetInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let start_time = SystemTime::now();
        let schema = Schema::arbitrary(SETTINGS.clone(), u)?;
        let hierarchy = schema.arbitrary_hierarchy(u)?;
        let policy = schema.arbitrary_policy(&hierarchy, u)?;

        let requests = [
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
            schema.arbitrary_request(&hierarchy, u)?,
        ];
        let all_entities = Entities::try_from(hierarchy).map_err(|_| Error::NotEnoughData)?;
        let entities = drop_some_entities(all_entities, u)?;
        let duration_since_start = SystemTime::now()
            .duration_since(start_time)
            .expect("Time went backwards");
        let gen_time = duration_since_start.as_secs_f64()
            + duration_since_start.subsec_nanos() as f64 / 1_000_000_000.0;

        Ok(Self {
            schema,
            entities,
            policy,
            requests,
            gen_time,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(&[
            Schema::arbitrary_size_hint(depth),
            HierarchyGenerator::size_hint(depth),
            Schema::arbitrary_policy_size_hint(&SETTINGS, depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
            Schema::arbitrary_request_size_hint(depth),
        ])
    }
}

impl TycheFormat for FuzzTargetInput {
    fn to_tyche(&self) -> TycheTest {
        let schema = self.schema.schemafile_string();
        let policy = self.policy.to_string();
        let representation = json!({
            "schema": schema,
            "policy": policy,
            "requests": self.requests.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        });
        // let features = match self.entities.to_json_value() {
        //     Ok(value) => value,
        //     Err(_) => json!({}),
        // };
        TycheTest {
            representation: representation.to_string(),
            property: "abac-type-directed".to_string(),
            features: self.get_features(),
            ..Default::default()
        }
    }
}

impl FuzzTargetInput {
    fn get_features(&self) -> serde_json::Value {
        let mut input_features = json!({});
        let namespace = &self.schema.schema;
        let namespace_name = match self.schema.namespace.as_ref() {
            None => String::new(),
            Some(name) => name.namespace(),
        };
        input_features["namespace_name_len"] = json!(namespace_name.len());
        input_features["num_actions"] = json!(namespace.actions.len());
        input_features["num_entity_types"] = json!(namespace.entity_types.len());
        input_features["num_common_types"] = json!(namespace.common_types.len());
        input_features["validation_errors"] = json!(0);
        input_features
    }
}

// Type-directed fuzzing of ABAC hierarchy/policy/requests.
fn test_fuzz_input(input: &FuzzTargetInput) {
    let exec_start_time = SystemTime::now();

    initialize_log();

    let mut obs_out = input.to_tyche();

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
    obs_out.features["total_auth_errors"] = json!(total_auth_errors);

    if let Ok(_) = std::env::var("DRT_OBSERVABILITY") {
        let duration_since_gen = SystemTime::now()
            .duration_since(exec_start_time)
            .expect("Time went backwards");
        let test_name = std::env::var("FUZZ_TARGET").unwrap_or("fuzz-target".to_string());

        obs_out.timing["generate"] = json!(input.gen_time);
        obs_out.timing["execute"] = json!(
            duration_since_gen.as_secs_f64()
                + duration_since_gen.subsec_nanos() as f64 / 1_000_000_000.0
        );
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

fn main() {
    bolero::check!()
        .with_arbitrary::<FuzzTargetInput>()
        .for_each(|value| test_fuzz_input(value));
}
