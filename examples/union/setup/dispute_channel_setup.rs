// fn setup_drp_covenant(
//     &mut self,
//     members: &Vec<Member>,
//     utxo: &Utxo,
//     session_id: Uuid,
// ) -> Result<()> {
//     // TODO we don't need to create the B => A covenant when B is a challenger
//     let my_address = self.address()?.clone();

//     // Create a sorted list of members to have a canonical order of pairs.
//     let mut sorted_members = members.clone();
//     sorted_members.sort_by(|a, b| a.address.cmp(&b.address));

//     for i in 0..sorted_members.len() {
//         for j in (i + 1)..sorted_members.len() {
//             let member1 = &sorted_members[i];
//             let member2 = &sorted_members[j];

//             let op1_address = member1.address()?;
//             let op2_address = member2.address()?;

//             // Check if the current operator is part of the pair
//             if my_address == *op1_address || my_address == *op2_address {
//                 // Skip covenant generation if both members are Challengers
//                 if matches!(member1.role, Role::Challenger)
//                     && matches!(member2.role, Role::Challenger)
//                 {
//                     info!("Skipping DRP covenant generation between two Challengers: {:?} and {:?}", op1_address, op2_address);
//                     continue;
//                 }

//                 // Unlike pairwise keys, DRP covenants need to be created in both directions
//                 // Create covenant for op1_address -> op2_address
//                 // let covenant_id_1 = Uuid::new_v4();
//                 let namespace = Uuid::NAMESPACE_DNS;
//                 let name_to_hash = format!(
//                     "drp_covenant:{:?}:{:?}:{:?}",
//                     op1_address, op2_address, session_id
//                 );
//                 let covenant_id_1 = Uuid::new_v5(&namespace, name_to_hash.as_bytes());
//                 let participants_1 = vec![op1_address.clone(), op2_address.clone()];
//                 self.prepare_drp(covenant_id_1, member1, member2)?;
//                 self.bitvmx.setup(
//                     covenant_id_1,
//                     PROGRAM_TYPE_DRP.to_string(),
//                     participants_1,
//                     0,
//                 )?;

//                 let other_address_1 = self.get_counterparty_address(member1, member2)?;

//                 self.covenants.drp_covenants.push(DrpCovenant {
//                     covenant_id: covenant_id_1,
//                     counterparty: other_address_1.clone(),
//                 });

//                 // Create covenant for op2_address -> op1_address
//                 // let covenant_id_2 = Uuid::new_v4();
//                 let name_to_hash = format!(
//                     "drp_covenant:{:?}:{:?}:{:?}",
//                     op2_address, op1_address, session_id
//                 );
//                 let covenant_id_2 = Uuid::new_v5(&namespace, name_to_hash.as_bytes());
//                 let participants_2 = vec![op2_address.clone(), op1_address.clone()];
//                 self.prepare_drp(covenant_id_2, member2, member1)?;
//                 self.bitvmx.setup(
//                     covenant_id_2,
//                     PROGRAM_TYPE_DRP.to_string(),
//                     participants_2,
//                     0,
//                 )?;

//                 self.covenants.drp_covenants.push(DrpCovenant {
//                     covenant_id: covenant_id_2,
//                     counterparty: other_address_1.clone(),
//                 });

//                 info!(
//                     id = self.id,
//                     counterparty = ?other_address_1,
//                     covenant_1 = ?covenant_id_1,
//                     covenant_2 = ?covenant_id_2,
//                     "Setup DRP covenants"
//                 );
//             }
//         }
//     }

//     Ok(())
// }

// pub fn prepare_drp(
//     &mut self,
//     covenant_id: Uuid,
//     member1: &Member,
//     member2: &Member,
// ) -> Result<()> {
//     info!(
//         id = self.id,
//         "Preparing DRP covenant {} for {} and {}", covenant_id, member1.id, member2.id
//     );

//     // Get the pairwise aggregated key for this pair
//     let counterparty_address = self.get_counterparty_address(member1, member2)?;
//     let pair_aggregated_pub_key = self
//         .keyring
//         .pairwise_keys
//         .get(&counterparty_address)
//         .ok_or_else(|| {
//             anyhow::anyhow!(
//                 "Pairwise key not found for counterparty: {:?}",
//                 counterparty_address
//             )
//         })?;

//     let program_path = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml";
//     self.bitvmx.set_var(
//         covenant_id,
//         "program_definition",
//         VariableTypes::String(program_path.to_string()),
//     )?;

//     self.bitvmx.set_var(
//         covenant_id,
//         "aggregated",
//         VariableTypes::PubKey(pair_aggregated_pub_key.clone()),
//     )?;

//     self.bitvmx
//         .set_var(covenant_id, "FEE", VariableTypes::Number(10_000))?;

//     // TODO this txid should come from the peg-in setup?
//     let txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
//     let txid = bitcoin::Txid::from_str(txid_str)
//         .map_err(|e| anyhow::anyhow!("Failed to parse txid: {}", e))?;

//     let initial_utxo = Utxo::new(txid, 4, 200_000, pair_aggregated_pub_key);
//     let prover_win_utxo = Utxo::new(txid, 2, 10_500, pair_aggregated_pub_key);

//     // TODO: this is not the right initial spending condition for Union. Check the Miro diagram.
//     let initial_spending_condition = vec![
//         timelock(
//             TIMELOCK_BLOCKS,
//             &self.keyring.take_aggregated_key.unwrap(),
//             SignMode::Aggregate,
//         ), //convert to timelock
//         check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
//     ];

//     let initial_output_type = external_fund_tx(
//         &self.keyring.take_aggregated_key.unwrap(),
//         initial_spending_condition,
//         200_000,
//     )?;

//     let prover_win_spending_condition = vec![
//         check_aggregated_signature(
//             &self.keyring.take_aggregated_key.unwrap(),
//             SignMode::Aggregate,
//         ), //convert to timelock
//         check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
//     ];

//     let prover_win_output_type = external_fund_tx(
//         &self.keyring.take_aggregated_key.unwrap(),
//         prover_win_spending_condition,
//         10_500,
//     )?;

//     self.bitvmx.set_var(
//         covenant_id,
//         "utxo",
//         VariableTypes::Utxo((
//             initial_utxo.txid,
//             initial_utxo.vout,
//             Some(initial_utxo.amount),
//             Some(initial_output_type),
//         )),
//     )?;

//     self.bitvmx.set_var(
//         covenant_id,
//         "utxo_prover_win_action",
//         VariableTypes::Utxo((
//             prover_win_utxo.txid,
//             prover_win_utxo.vout,
//             Some(prover_win_utxo.amount),
//             Some(prover_win_output_type),
//         )),
//     )?;

//     sleep(Duration::from_secs(20));
//     Ok(())
// }
