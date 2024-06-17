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

use afl::fuzz;
use arbitrary::{Arbitrary, Unstructured};
use cedar_fuzz_lib::harnesses::test_eval_type_directed;
use cedar_fuzz_lib::fuzz_inputs::eval_type_directed::EvalTypeDirectedFuzzTargetInput;
use cedar_drt::*;

// Type-directed fuzzing of expression evaluation.
fn main() {
    fuzz!(|data: &[u8]| {
        initialize_log();
        let mut input_data = Unstructured::new(data);
        let input = EvalTypeDirectedFuzzTargetInput::arbitrary(&mut input_data);
        test_eval_type_directed(input);
    });
}