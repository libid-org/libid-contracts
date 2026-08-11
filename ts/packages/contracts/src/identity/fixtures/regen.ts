// Writes the shared bind-encoding fixture from the encoders. The file lives
// beside `BindEncoding.t.sol`, which decodes the same bytes from the other
// side. Run after changing a proof layout:
// `pnpm -C ts/packages/contracts regen:fixtures`.
import { writeFileSync } from 'node:fs'
import { GITHUB_FIXTURE, GOOGLE_FIXTURE, X_FIXTURE } from '../bind.fixtures.js'
import { encodeGitHubProof, encodeGoogleProof, encodeXProof } from '../bind.js'

writeFileSync(
  new URL(
    '../../../../../../solidity/contracts/identity/test/fixtures/bind-encoding.json',
    import.meta.url,
  ),
  `${JSON.stringify(
    {
      github: encodeGitHubProof(GITHUB_FIXTURE),
      x: encodeXProof(X_FIXTURE),
      google: encodeGoogleProof(GOOGLE_FIXTURE),
    },
    null,
    2,
  )}\n`,
)
