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
use log::{debug, info};
use serde::Serialize;
use serde_json::json;
use std::io::Write;
use std::{convert::TryFrom, time::SystemTime};

use crate::*;

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

/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 8 associated requests
#[derive(Debug, Clone, Serialize)]
pub struct ABACTypeDirectedFuzzTargetInput {
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
    pub gen_time: f64,
    pub valid: bool,
}

impl<'a> Arbitrary<'a> for ABACTypeDirectedFuzzTargetInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut valid = true;
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
        let all_entities = Entities::try_from(hierarchy).map_err(|err| {
            format!("Failed to generate entities: {}", err);
            valid = false;
            Error::NotEnoughData
        })?;
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
            valid,
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
    
    fn arbitrary_take_rest(mut u: Unstructured<'a>) -> Result<ABACTypeDirectedFuzzTargetInput, arbitrary::Error> {
        Self::arbitrary(&mut u)
    }
}

impl TycheFormat for ABACTypeDirectedFuzzTargetInput {
    fn to_tyche(&self) -> TycheTest {
        let schema = self.schema.schemafile_string();
        let policy = self.policy.to_string();
        let representation = json!({
            "schema": schema,
            "policy": policy,
            "requests": self.requests.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        });
        TycheTest {
            representation: representation.to_string(),
            property: "abac-type-directed".to_string(),
            features: self.get_features(),
            ..Default::default()
        }
    }
}

impl ABACTypeDirectedFuzzTargetInput {
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