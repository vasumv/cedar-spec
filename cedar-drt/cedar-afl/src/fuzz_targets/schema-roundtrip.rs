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
use cedar_drt_inner::schemas::equivalence_check;
use cedar_drt_inner::*;
use cedar_policy_generators::{schema::Schema, settings::ABACSettings};
use cedar_policy_validator::SchemaFragment;
use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use log::info;
use serde::Serialize;
use similar_asserts::SimpleDiff;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize)]
struct Input {
    pub schema: SchemaFragment,
    pub gen_time: f64,
}

/// settings for this fuzz target
const SETTINGS: ABACSettings = ABACSettings {
    match_types: false,
    enable_extensions: true,
    max_depth: 3,
    max_width: 7,
    enable_additional_attributes: false,
    enable_like: true,
    // ABAC fuzzing restricts the use of action because it is used to generate
    // the corpus tests which will be run on Cedar and CedarCLI.
    // These packages only expose the restricted action behavior.
    enable_action_groups_and_attrs: false,
    enable_arbitrary_func_call: true,
    enable_unknowns: false,
    enable_action_in_constraints: true,
    enable_unspecified_apply_spec: true,
};

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let start_time = SystemTime::now();
        let mut input_features = json!({});
        let arb_schema = Schema::arbitrary(SETTINGS.clone(), u)?;
        let namespace = arb_schema.schema;
        let name = arb_schema.namespace;

        let namespace_name = name.as_ref().unwrap().namespace();
        input_features["namespace"] = json!(namespace_name);
        input_features["num_actions"] = json!(&namespace.actions.len());
        input_features["num_entity_types"] = json!(&namespace.entity_types.len());
        input_features["num_common_types"] = json!(&namespace.common_types.len());

        let schema = SchemaFragment(HashMap::from([(name, namespace)]));
        let duration_since_start = SystemTime::now()
            .duration_since(start_time)
            .expect("Time went backwards");
        let gen_time = duration_since_start.as_secs_f64()
            + duration_since_start.subsec_nanos() as f64 / 1_000_000_000.0;

        Ok(Self { schema, gen_time })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        Schema::arbitrary_size_hint(depth)
    }
}

impl TycheFormat for Input {
    fn to_tyche(&self) -> TycheTest {
        TycheTest {
            representation: self.schema.as_natural_schema().unwrap(),
            ..Default::default()
        }
    }
}

fuzz_target!(|i: Input| {
    let src = i
        .schema
        .as_natural_schema()
        .expect("Failed to convert schema into a human readable schema");
    let (parsed, _) = SchemaFragment::from_str_natural(&src)
        .expect("Failed to parse converted human readable schema");
    if let Err(msg) = equivalence_check(i.schema.clone(), parsed.clone()) {
        println!("Schema: {src}");
        println!(
            "{}",
            SimpleDiff::from_str(
                &format!("{:#?}", i.schema),
                &format!("{:#?}", parsed),
                "Initial Schema",
                "Human Round tripped"
            )
        );
        panic!("{msg}");
    }
    if let Ok(_) = std::env::var("DRT_OBSERVABILITY") {
        let duration_since_gen = SystemTime::now()
            .duration_since(exec_start_time)
            .expect("Time went backwards");
        let test_name = std::env::var("FUZZ_TARGET").unwrap();

        obs_out.timing["generate"] = json!(i.gen_time);
        obs_out.timing["execute"] = json!(
            duration_since_gen.as_secs_f64()
                + duration_since_gen.subsec_nanos() as f64 / 1_000_000_000.0
        );
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
        writeln!(file, "{obs_out_json}").expect("Error writing to tyche file");
    }
});
