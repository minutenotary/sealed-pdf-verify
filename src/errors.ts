/** Thrown when a proof sidecar cannot be understood at all (not a verification failure). */
export class ProofFormatError extends Error {
  override readonly name = 'ProofFormatError';
}
