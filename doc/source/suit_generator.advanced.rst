suit-generator advanced usage
=============================

suit-generator offers initialization of low level representation of SUIT envelope.

Mentioned representation offers much more control over possible child elements and envelope content.

This might be helpful during testing, especially if negative cases are required like corrupted envelopes or unsupported elements.

 .. code-block:: python

   from suit_generator.suit import SuitEnvelopeTagged, SuitEnvelopeSimplifiedTagged

SuitEnvelopeTagged is a standard representation of all elements in the SUIT envelope.

  .. code-block:: python

    SuitEnvelopeTagged
     |-> SuitEnvelope
          |-> suit_manifest: cbstr(SuitManifest),
          |-> suit_authentication_wrapper: cbstr(SuitAuthentication),
          |-> suit_dependency_resolution: cbstr(SuitCommandSequence),
          |-> suit_payload_fetch: cbstr(SuitCommandSequence),
          |-> suit_candidate_verification: cbstr(SuitCommandSequence),
          |-> suit_install: cbstr(SuitCommandSequence),
          |-> suit_text: cbstr(SuitTextMap),
          |-> suit_integrated_payloads: SuitIntegratedPayloadMap,


SuitEnvelopeSimplifiedTagged is a representation of first-level elements required to sign an envelope (authentication wrapper is fully presented while other elements are present as cbor encoded)

  .. code-block:: python

    SuitEnvelopeTaggedSimplified
     |-> SuitEnvelopeSimplified
          |-> suit_manifest: SuitBstr,
          |-> suit_authentication_wrapper: cbstr(SuitAuthentication),
          |-> suit_dependency_resolution: SuitBstr,
          |-> suit_payload_fetch: SuitBstr,
          |-> suit_candidate_verification: SuitBstr,
          |-> suit_install: SuitBstr,
          |-> suit_text: SuitBstr,
          |-> suit_integrated_payloads: SuitIntegratedPayloadMap,

Simplified representation can be used to calculate digest and sign corrupted manifest since this element is not parsed.


Example usage:

 .. code-block:: python

    from suit_generator.suit import SuitEnvelopeTagged
    from suit_generator.suit.types.keys import suit_manifest

   self.envelope = SuitEnvelopeTagged.from_obj(json.loads(suit_configuration))
   del self.envelope.SuitEnvelopeTagged.value.SuitEnvelope[suit_manifest]


Representation of envelope can be also initialized directly from binary files:
  .. code-block:: python

     from suit_generator.suit import SuitEnvelopeTaggedSimplified
     from pathlib import Path
     self.envelope = SuitEnvelopeTaggedSimplified.from_cbor(binascii.a2b_hex(envelope_hex))
     key_path = Path('/some/directory/')
     private_key_name = 'key_private.pem'
     with open(key_path / private_key_name, "rb") as key:
         private_key = key.read()
         self.envelope.sign(private_key)
     hex_representation = self.envelope.to_cbor().hex()


suit_generator.suit.envelope module
-----------------------------------

.. automodule:: suit_generator.suit.envelope
   :members:
   :exclude-members: SuitEnvelope, SuitEnvelopeSimplified
   :show-inheritance: