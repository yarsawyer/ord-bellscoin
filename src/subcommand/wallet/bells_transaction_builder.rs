// This builder is used to construct a Bells transaction

use {
    super::*,
    bitcoin::{
      blockdata::{locktime::PackedLockTime, witness::Witness},
      util::amount::Amount,
    },
    std::collections::{BTreeMap, BTreeSet},
  };
  
  #[derive(Debug, PartialEq)]
  pub enum Error {
    DuplicateAddress(Address),
    Dust {
      output_value: Amount,
      dust_value: Amount,
    },
    NotEnoughCardinalUtxos,
    NotInWallet(SatPoint),
    OutOfRange(SatPoint, u64),
    UtxoContainsAdditionalInscription {
      outgoing_satpoint: SatPoint,
      inscribed_satpoint: SatPoint,
      inscription_id: InscriptionId,
    },
    ValueOverflow,
  }
  
  #[derive(Debug, PartialEq)]
  enum Target {
    Value(Amount),
    Postage,
  }
  
  impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
        Error::Dust {
          output_value,
          dust_value,
        } => write!(f, "output value is below dust value: {output_value} < {dust_value}"),
        Error::NotInWallet(outgoing_satpoint) => write!(f, "outgoing satpoint {outgoing_satpoint} not in wallet"),
        Error::OutOfRange(outgoing_satpoint, maximum) => write!(f, "outgoing satpoint {outgoing_satpoint} offset higher than maximum {maximum}"),
        Error::NotEnoughCardinalUtxos => write!(
          f,
          "wallet does not contain enough cardinal UTXOs, please add additional funds to wallet."
        ),
        Error::UtxoContainsAdditionalInscription {
          outgoing_satpoint,
          inscribed_satpoint,
          inscription_id,
        } => write!(
          f,
          "cannot send {outgoing_satpoint} without also sending inscription {inscription_id} at {inscribed_satpoint}"
        ),
        Error::ValueOverflow => write!(f, "arithmetic overflow calculating value"),
        Error::DuplicateAddress(address) => write!(f, "duplicate input address: {address}"),
      }
    }
  }
  
  impl std::error::Error for Error {}
  
  #[derive(Debug)]
  pub struct BellsTransactionBuilder {
    amounts: BTreeMap<OutPoint, Amount>,
    change_addresses: BTreeSet<Address>,
    fee_rate: FeeRate,
    inputs: Vec<OutPoint>,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    outgoing: SatPoint,
    outputs: Vec<(Address, Amount)>,
    recipient: Address,
    unused_change_addresses: Vec<Address>,
    utxos: BTreeSet<OutPoint>,
    target: Target,
  }
  
  type Result<T> = std::result::Result<T, Error>;
  
  impl BellsTransactionBuilder {
    const ADDITIONAL_INPUT_VBYTES: usize = 58;
    const ADDITIONAL_OUTPUT_VBYTES: usize = 43;
    const MAX_POSTAGE: Amount = Amount::from_sat(5 * 100_000);
    pub(crate) const TARGET_POSTAGE: Amount = Amount::from_sat(100_000);
  
    pub fn build_transaction_with_postage(
      outgoing: SatPoint,
      inscriptions: BTreeMap<SatPoint, InscriptionId>,
      amounts: BTreeMap<OutPoint, Amount>,
      recipient: Address,
      change: [Address; 2],
      fee_rate: FeeRate,
    ) -> Result<Transaction> {
      Self::new(
        outgoing,
        inscriptions,
        amounts,
        recipient,
        change,
        fee_rate,
        Target::Postage,
      )?
      .build_transaction()
    }
  
    pub fn build_transaction_with_value(
      outgoing: SatPoint,
      inscriptions: BTreeMap<SatPoint, InscriptionId>,
      amounts: BTreeMap<OutPoint, Amount>,
      recipient: Address,
      change: [Address; 2],
      fee_rate: FeeRate,
      output_value: Amount,
    ) -> Result<Transaction> {
      let dust_value = recipient.script_pubkey().dust_value();
  
      if output_value < dust_value {
        return Err(Error::Dust {
          output_value,
          dust_value,
        });
      }
  
      Self::new(
        outgoing,
        inscriptions,
        amounts,
        recipient,
        change,
        fee_rate,
        Target::Value(output_value),
      )?
      .build_transaction()
    }
  
    fn build_transaction(self) -> Result<Transaction> {
      self
        .select_outgoing()?
        .align_outgoing()
        .pad_alignment_output()?
        .add_value()?
        .strip_value()
        .deduct_fee()
        .build()
    }
  
    fn new(
      outgoing: SatPoint,
      inscriptions: BTreeMap<SatPoint, InscriptionId>,
      amounts: BTreeMap<OutPoint, Amount>,
      recipient: Address,
      change: [Address; 2],
      fee_rate: FeeRate,
      target: Target,
    ) -> Result<Self> {
      if change.contains(&recipient) {
        return Err(Error::DuplicateAddress(recipient));
      }
  
      if change[0] == change[1] {
        return Err(Error::DuplicateAddress(change[0].clone()));
      }
  
      Ok(Self {
        utxos: amounts.keys().cloned().collect(),
        amounts,
        change_addresses: change.iter().cloned().collect(),
        fee_rate,
        inputs: Vec::new(),
        inscriptions,
        outgoing,
        outputs: Vec::new(),
        recipient,
        unused_change_addresses: change.to_vec(),
        target,
      })
    }
  
    fn select_outgoing(mut self) -> Result<Self> {
      for (inscribed_satpoint, inscription_id) in &self.inscriptions {
        if self.outgoing.outpoint == inscribed_satpoint.outpoint
          && self.outgoing.offset != inscribed_satpoint.offset
        {
          return Err(Error::UtxoContainsAdditionalInscription {
            outgoing_satpoint: self.outgoing,
            inscribed_satpoint: *inscribed_satpoint,
            inscription_id: *inscription_id,
          });
        }
      }
  
      let amount = *self
        .amounts
        .get(&self.outgoing.outpoint)
        .ok_or(Error::NotInWallet(self.outgoing))?;
  
      if self.outgoing.offset >= amount.to_sat() {
        return Err(Error::OutOfRange(self.outgoing, amount.to_sat() - 1));
      }
  
      self.utxos.remove(&self.outgoing.outpoint);
      self.inputs.push(self.outgoing.outpoint);
      self.outputs.push((self.recipient.clone(), amount));
  
      tprintln!(
        "selected outgoing outpoint {} with value {}",
        self.outgoing.outpoint,
        amount.to_sat()
      );
  
      Ok(self)
    }
  
    fn align_outgoing(mut self) -> Self {
      assert_eq!(self.outputs.len(), 1, "invariant: only one output");
  
      assert_eq!(
        self.outputs[0].0, self.recipient,
        "invariant: first output is recipient"
      );
  
      let sat_offset = self.calculate_sat_offset();
      if sat_offset == 0 {
        tprintln!("outgoing is aligned");
      } else {
        tprintln!("aligned outgoing with {sat_offset} sat padding output");
        self.outputs.insert(
          0,
          (
            self
              .unused_change_addresses
              .pop()
              .expect("not enough change addresses"),
            Amount::from_sat(sat_offset),
          ),
        );
        self.outputs.last_mut().expect("no output").1 -= Amount::from_sat(sat_offset);
      }
  
      self
    }
  
    fn pad_alignment_output(mut self) -> Result<Self> {
      if self.outputs[0].0 == self.recipient {
        tprintln!("no alignment output");
      } else {
        let dust_limit = self.recipient.script_pubkey().dust_value();
        if self.outputs[0].1 >= dust_limit {
          tprintln!("no padding needed");
        } else {
          let (utxo, size) = self.select_cardinal_utxo(dust_limit - self.outputs[0].1)?;
          self.inputs.insert(0, utxo);
          self.outputs[0].1 += size;
          tprintln!(
            "padded alignment output to {} with additional {size} nook input",
            self.outputs[0].1
          );
        }
      }
  
      Ok(self)
    }
  
    fn add_value(mut self) -> Result<Self> {
      let estimated_fee = self.estimate_fee();
  
      let min_value = match self.target {
        Target::Postage => self.outputs.last().unwrap().0.script_pubkey().dust_value(),
        Target::Value(value) => value,
      };
  
      let total = min_value
        .checked_add(estimated_fee)
        .ok_or(Error::ValueOverflow)?;
  
      if let Some(deficit) = total.checked_sub(self.outputs.last().unwrap().1) {
        if deficit > Amount::ZERO {
          let needed = deficit
            .checked_add(self.fee_rate.fee(Self::ADDITIONAL_INPUT_VBYTES))
            .ok_or(Error::ValueOverflow)?;
          let (utxo, value) = self.select_cardinal_utxo(needed)?;
          self.inputs.push(utxo);
          self.outputs.last_mut().unwrap().1 += value;
          tprintln!("added {value} nook input to cover {deficit} nook deficit");
        }
      }
  
      Ok(self)
    }
  
    fn strip_value(mut self) -> Self {
      let sat_offset = self.calculate_sat_offset();
  
      let total_output_amount = self
        .outputs
        .iter()
        .map(|(_address, amount)| *amount)
        .sum::<Amount>();
  
      self
        .outputs
        .iter()
        .find(|(address, _amount)| address == &self.recipient)
        .expect("couldn't find output that contains the index");
  
      let value = total_output_amount - Amount::from_sat(sat_offset);
  
      if let Some(excess) = value.checked_sub(self.fee_rate.fee(self.estimate_vbytes())) {
        let (max, target) = match self.target {
          Target::Postage => (Self::MAX_POSTAGE, Self::TARGET_POSTAGE),
          Target::Value(value) => (value, value),
        };
  
        if excess > max
          && value.checked_sub(target).unwrap()
            > self
              .unused_change_addresses
              .last()
              .unwrap()
              .script_pubkey()
              .dust_value()
              + self
                .fee_rate
                .fee(self.estimate_vbytes() + Self::ADDITIONAL_OUTPUT_VBYTES)
        {
          tprintln!("stripped {} sats", (value - target).to_sat());
          self.outputs.last_mut().expect("no outputs found").1 = target;
          self.outputs.push((
            self
              .unused_change_addresses
              .pop()
              .expect("not enough change addresses"),
            value - target,
          ));
        }
      }
  
      self
    }
  
    fn deduct_fee(mut self) -> Self {
      let sat_offset = self.calculate_sat_offset();
  
      let fee = self.estimate_fee();
  
      let total_output_amount = self
        .outputs
        .iter()
        .map(|(_address, amount)| *amount)
        .sum::<Amount>();
  
      let (_address, last_output_amount) = self
        .outputs
        .last_mut()
        .expect("No output to deduct fee from");
  
      assert!(
        total_output_amount.checked_sub(fee).unwrap() > Amount::from_sat(sat_offset),
        "invariant: deducting fee does not consume sat",
      );
  
      assert!(
        *last_output_amount >= fee,
        "invariant: last output can pay fee: {} {}",
        *last_output_amount,
        fee,
      );
  
      *last_output_amount -= fee;
  
      self
    }
  
    /// Estimate the size in virtual bytes of the transaction under construction.
    /// We initialize wallets with taproot descriptors only, so we know that all
    /// inputs are taproot key path spends, which allows us to know that witnesses
    /// will all consist of single Schnorr signatures.
    fn estimate_vbytes(&self) -> usize {
      Self::estimate_vbytes_with(
        self.inputs.len(),
        self
          .outputs
          .iter()
          .map(|(address, _amount)| address)
          .cloned()
          .collect(),
      )
    }
  
    fn estimate_vbytes_with(inputs: usize, outputs: Vec<Address>) -> usize {
      Transaction {
        version: 1,
        lock_time: PackedLockTime::ZERO,
        input: (0..inputs)
          .into_iter()
          .map(|_| TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
          })
          .collect(),
        output: outputs
          .into_iter()
          .map(|address| TxOut {
            value: 0,
            script_pubkey: address.script_pubkey(),
          })
          .collect(),
      }
      .vsize()
    }
  
    fn estimate_fee(&self) -> Amount {
      self.fee_rate.fee(self.estimate_vbytes())
    }
  
    fn build(self) -> Result<Transaction> {
      let recipient = self.recipient.script_pubkey();
      let transaction = Transaction {
        version: 1,
        lock_time: PackedLockTime::ZERO,
        input: self
          .inputs
          .iter()
          .map(|outpoint| TxIn {
            previous_output: *outpoint,
            script_sig: Script::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
          })
          .collect(),
        output: self
          .outputs
          .iter()
          .map(|(address, amount)| TxOut {
            value: amount.to_sat(),
            script_pubkey: address.script_pubkey(),
          })
          .collect(),
      };
  
      assert_eq!(
        self
          .amounts
          .iter()
          .filter(|(outpoint, amount)| *outpoint == &self.outgoing.outpoint
            && self.outgoing.offset < amount.to_sat())
          .count(),
        1,
        "invariant: outgoing nook is contained in utxos"
      );
  
      assert_eq!(
        transaction
          .input
          .iter()
          .filter(|tx_in| tx_in.previous_output == self.outgoing.outpoint)
          .count(),
        1,
        "invariant: inputs spend outgoing sat"
      );
  
      let mut sat_offset = 0;
      let mut found = false;
      for tx_in in &transaction.input {
        if tx_in.previous_output == self.outgoing.outpoint {
          sat_offset += self.outgoing.offset;
          found = true;
          break;
        } else {
          sat_offset += self.amounts[&tx_in.previous_output].to_sat();
        }
      }
      assert!(found, "invariant: outgoing nook is found in inputs");
  
      let mut output_end = 0;
      let mut found = false;
      for tx_out in &transaction.output {
        output_end += tx_out.value;
        if output_end > sat_offset {
          assert_eq!(
            tx_out.script_pubkey, recipient,
            "invariant: outgoing nook is sent to recipient"
          );
          found = true;
          break;
        }
      }
      assert!(found, "invariant: outgoing nook is found in outputs");
  
      assert_eq!(
        transaction
          .output
          .iter()
          .filter(|tx_out| tx_out.script_pubkey == self.recipient.script_pubkey())
          .count(),
        1,
        "invariant: recipient address appears exactly once in outputs",
      );
  
      assert!(
        self
          .change_addresses
          .iter()
          .map(|change_address| transaction
            .output
            .iter()
            .filter(|tx_out| tx_out.script_pubkey == change_address.script_pubkey())
            .count())
          .all(|count| count <= 1),
        "invariant: change addresses appear at most once in outputs",
      );
  
      let mut offset = 0;
      for output in &transaction.output {
        if output.script_pubkey == self.recipient.script_pubkey() {
          let slop = self.fee_rate.fee(Self::ADDITIONAL_OUTPUT_VBYTES);
  
          match self.target {
            Target::Postage => {
              assert!(
                Amount::from_sat(output.value) <= Self::MAX_POSTAGE + slop,
                "invariant: excess postage is stripped"
              );
            }
            Target::Value(value) => {
              assert!(
                Amount::from_sat(output.value).checked_sub(value).unwrap()
                  <= self
                    .change_addresses
                    .iter()
                    .map(|address| address.script_pubkey().dust_value())
                    .max()
                    .unwrap_or_default()
                    + slop,
                "invariant: output equals target value",
              );
            }
          }
          assert_eq!(
            offset, sat_offset,
            "invariant: nook is at first position in recipient output"
          );
        } else {
          assert!(
            self
              .change_addresses
              .iter()
              .any(|change_address| change_address.script_pubkey() == output.script_pubkey),
            "invariant: all outputs are either change or recipient: unrecognized output {}",
            output.script_pubkey
          );
        }
        offset += output.value;
      }
  
      let mut actual_fee = Amount::ZERO;
      for input in &transaction.input {
        actual_fee += self.amounts[&input.previous_output];
      }
      for output in &transaction.output {
        actual_fee -= Amount::from_sat(output.value);
      }
  
      let mut modified_tx = transaction.clone();
      for input in &mut modified_tx.input {
        input.witness = Witness::from_vec(vec![vec![0; 64]]);
      }
      let expected_fee = self.fee_rate.fee(modified_tx.vsize());
  
      assert_eq!(
        actual_fee, expected_fee,
        "invariant: fee estimation is correct",
      );
  
      for tx_out in &transaction.output {
        assert!(
          Amount::from_sat(tx_out.value) >= tx_out.script_pubkey.dust_value(),
          "invariant: all outputs are above dust limit",
        );
      }
  
      Ok(transaction)
    }
  
    fn calculate_sat_offset(&self) -> u64 {
      let mut sat_offset = 0;
      for outpoint in &self.inputs {
        if *outpoint == self.outgoing.outpoint {
          return sat_offset + self.outgoing.offset;
        } else {
          sat_offset += self.amounts[outpoint].to_sat();
        }
      }
  
      panic!("Could not find outgoing sat in inputs");
    }
  
    fn select_cardinal_utxo(&mut self, minimum_value: Amount) -> Result<(OutPoint, Amount)> {
      let mut found = None;
  
      let inscribed_utxos = self
        .inscriptions
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();
  
      for utxo in &self.utxos {
        if inscribed_utxos.contains(utxo) {
          continue;
        }
  
        let value = self.amounts[utxo];
  
        if value >= minimum_value {
          found = Some((*utxo, value));
          break;
        }
      }
  
      let (utxo, value) = found.ok_or(Error::NotEnoughCardinalUtxos)?;
  
      self.utxos.remove(&utxo);
  
      Ok((utxo, value))
    }
  }
  
  