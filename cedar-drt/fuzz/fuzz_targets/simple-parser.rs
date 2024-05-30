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

use cedar_drt_inner::{fuzz_target, TycheTest};
use cedar_policy_core::parser::err::{ParseError, ToASTErrorKind};
use cedar_policy_core::parser::parse_policyset;
use serde_json::json;
use std::io::Write;
use std::path::Path;

fuzz_target!(|input: String| {
    // Write to jsonl file for Tyche
    let start_time = std::time::SystemTime::now();

    // No conversion to FuzzTargetInput, so no real generation time

    let test_name = std::env::var("FUZZ_TARGET").unwrap();
    let mut obs_out = TycheTest {
        representation: input.clone(),
        property: test_name.clone(),
        ..Default::default()
    };
    // Ensure the parser does not crash
    #[allow(clippy::single_match)]
    let parse_out = parse_policyset(&input);
    let duration_since_gen = std::time::SystemTime::now()
        .duration_since(start_time)
        .expect("Time went backwards");

    obs_out.timing["execute"] = json!(duration_since_gen.as_secs_f64());

    match parse_out {
        Ok(_) => (),
        Err(errs) => {
            // Also check that we don't see a few specific errors.
            // `AnnotationInvariantViolation` and `MembershipInvariantViolation`
            // are documented as only being returned for internal invariant violations.  It's not
            // entirely clear when `MissingNodeData` might be returned, but I don't believe it
            // should be possible, and, practically, it doesn't make this target fail.
            obs_out.status = "failed".to_string();
            obs_out.status_reason = "Parse error!".to_string();
            assert!(
                !errs.0.iter().any(|e| matches!(
                e,
                ParseError::ToAST(e) if matches!(e.kind(),
                    ToASTErrorKind::AnnotationInvariantViolation
                        | ToASTErrorKind::MembershipInvariantViolation
                        | ToASTErrorKind::MissingNodeData)
                )),
                "{:?}",
                errs
            )
        }
    };
    if let Ok(_) = std::env::var("DRT_OBSERVABILITY") {
        // Make a directory called tyche-out/ in the current directory
        let tyche_out = Path::new("tyche-out");
        std::fs::create_dir_all(tyche_out).expect("Error creating tyche-out directory");

        // Make a file in tyche-out with the name of the test followed by _testcases.jsonl
        let tyche_file_path = tyche_out.join(format!("{}_testcases.jsonl", test_name));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tyche_file_path)
            .unwrap();
        let obs_out = serde_json::to_value(&obs_out).unwrap();
        writeln!(file, "{obs_out}").expect("Error writing to tyche file");
    }
});
