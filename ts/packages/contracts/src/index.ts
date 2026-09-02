/// @libid/contracts — typed viem-ready ABIs for every contract, a call builder
/// for every state-changing function, and the identity helper layer. Subpath
/// imports work too: `@libid/contracts/abis`, `@libid/contracts/calls` and
/// `@libid/contracts/identity`.

export * from './abis/index.js'
export type { Call } from './call.js'
export * as calls from './calls/index.js'
export * from './identity/index.js'
