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
use arbitrary::{Arbitrary, Unstructured};
use cedar_drt::{ast::Expr, *};
use cedar_policy_core::ast;
use cedar_policy_core::entities::Entities;
use cedar_policy_generators::{
    abac::{ABACPolicy, ABACRequest},
    err::Error,
    hierarchy::HierarchyGenerator,
    schema::{arbitrary_schematype_with_bounded_depth, Schema},
    settings::ABACSettings,
};
use log::{debug, info};
use serde::Serialize;
use serde_json::json;
use utils::expr_to_est;
use std::io::Write;
use std::{convert::TryFrom, time::SystemTime};

use crate::*;

/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 8 associated requests
#[derive(Debug, Clone, Serialize)]
pub struct EvalTypeDirectedFuzzTargetInput {
    /// generated schema
    #[serde(skip)]
    pub schema: Schema,
    /// generated entity slice
    #[serde(skip)]
    pub entities: Entities,
    /// generated expression
    #[serde(serialize_with = "expr_to_est")]
    pub expression: Expr,
    /// the requests to try for this hierarchy and policy. We try 8 requests per
    /// policy/hierarchy
    #[serde(skip)]
    pub request: ABACRequest,
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

impl<'a> Arbitrary<'a> for EvalTypeDirectedFuzzTargetInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let schema = Schema::arbitrary(SETTINGS.clone(), u)?;
        let hierarchy = schema.arbitrary_hierarchy(u)?;
        let toplevel_type = arbitrary_schematype_with_bounded_depth(
            &SETTINGS,
            schema.entity_types(),
            SETTINGS.max_depth,
            u,
        )?;
        let expr_gen = schema.exprgenerator(Some(&hierarchy));
        let expression =
            expr_gen.generate_expr_for_schematype(&toplevel_type, SETTINGS.max_depth, u)?;

        let request = schema.arbitrary_request(&hierarchy, u)?;
        let all_entities = Entities::try_from(hierarchy).map_err(Error::EntitiesError)?;
        let entities = drop_some_entities(all_entities, u)?;
        Ok(Self {
            schema,
            entities,
            expression,
            request,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and_all(&[
            Schema::arbitrary_size_hint(depth),
            HierarchyGenerator::size_hint(depth),
            Schema::arbitrary_policy_size_hint(&SETTINGS, depth),
            Schema::arbitrary_request_size_hint(depth),
        ])
    }
}

impl TycheFormat for EvalTypeDirectedFuzzTargetInput {
    fn to_tyche(&self) -> TycheTest {
        let serialized = serde_json::to_string(&self).unwrap();
        let value: Value = serde_json::from_str(&serialized).unwrap();
        // Access the serialized expression
        let representation = json!({
            "schema": self.schema.schemafile_string(),
            "entities": self.entities.to_json_value().unwrap().to_string(),
            "expression": value.get("expression").unwrap().to_string(), 
            "principal": self.request.principal,
            "action": self.request.action,
            "resource": self.request.resource,
            "context": self.request.context,
        });
        TycheTest {
            representation: representation.to_string(),
            property: "eval-type-directed".to_string(),
            features: self.get_features(),
            ..Default::default()
        }
    }
}

impl EvalTypeDirectedFuzzTargetInput {
    fn get_features(&self) -> serde_json::Value {
        let input_features = json!({});
        input_features
    }
}