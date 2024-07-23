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

use arbitrary::{self, Arbitrary, Unstructured};
use ast::PolicyID;
use bolero::check;
use cedar_bolero_fuzz::{dump, run_auth_test, run_eval_test, time_function};
use cedar_drt::utils::expr_to_est;
use cedar_drt::*;
use cedar_policy::{Authorizer, Request};
use cedar_policy_core::{ast::Expr, entities::Entities};
use cedar_policy_generators::abac::{ABACPolicy, ABACRequest};
use cedar_policy_generators::err::Error;
use cedar_policy_generators::hierarchy::{self, Hierarchy, HierarchyGenerator};
use cedar_policy_generators::schema::{arbitrary_schematype_with_bounded_depth, Schema};
use cedar_policy_generators::settings::ABACSettings;
use cedar_policy_validator::SchemaFragment;
use log::{debug, info};
use serde::Serialize;
use std::convert::TryFrom;

/// Input expected by this fuzz target:
/// An ABAC hierarchy, policy, and 8 associated requests
#[derive(Debug)]
pub struct FuzzTargetInput {
    pub entities: Entities,
    /// generated policy
    pub policy: ast::Policy,
    /// the requests to try for this hierarchy and policy. We try 8 requests per
    /// policy/hierarchy
    pub requests: [ABACRequest; 8],
}

impl<'a> Arbitrary<'a> for FuzzTargetInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let est_policy: cedar_policy_core::est::Policy = u.arbitrary()?;
        let policy = est_policy
            .try_into_ast_policy(Some(PolicyID::from_string("policy0")))
            .map_err(|e| arbitrary::Error::IncorrectFormat)?;

        Ok(FuzzTargetInput {
            entities: u.arbitrary()?,
            policy: policy,
            requests: u.arbitrary()?,
        })
    }
}

fn main() {
    check!()
        .with_arbitrary::<FuzzTargetInput>()
        .for_each(|input| {
            initialize_log();
            let def_impl = LeanDefinitionalEngine::new();
            let policy = input.policy.clone();
            let mut policyset: ast::PolicySet = ast::PolicySet::new();
            let entities = input.entities.clone();
            policyset.add(policy.clone()).unwrap();
            debug!("Policies: {policyset}");
            debug!("Entities: {entities}");
            let requests = input
                .requests
                .clone()
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>();

            for request in requests.iter().cloned() {
                debug!("Request: {request}");
                let (_, total_dur) =
                    time_function(|| run_auth_test(&def_impl, request, &policyset, &entities));
                info!("{}{}", TOTAL_MSG, total_dur.as_nanos());
            }
        });
}
