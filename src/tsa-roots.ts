import { BUILT_IN_TSA_ROOTS, type BuiltInRoot } from './tsa-roots.generated.js';

export { BUILT_IN_TSA_ROOTS };
export type { BuiltInRoot };

/** PEM text of every built-in TSA root, one string per certificate file. */
export function builtInTsaRootsPem(): string[] {
  return BUILT_IN_TSA_ROOTS.map((r) => r.pem);
}
