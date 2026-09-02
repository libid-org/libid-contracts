/// The generated builders against a real chain.
///
/// Unit tests prove the calldata decodes back to what went in; they cannot
/// prove a contract accepts it. This deploys one and sends both shapes — a
/// payable builder whose `value` has to arrive as ether, and a nonpayable one
/// whose arguments have to land in the right order — then reads the balances
/// back. Without it, "generated" and "usable" are two different claims.
///
/// Skips when anvil is absent, like the OIDC proof-artifact tests do: foundry
/// is required to build the contracts this reads, so in CI it is always here.
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { createPublicClient, createWalletClient, http, parseEther } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { foundry } from 'viem/chains'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { wtia9Abi } from './abis/wtia9.js'
import { calls } from './index.js'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..')
const artifactPath = join(repoRoot, 'solidity', 'out', 'WTIA9.sol', 'WTIA9.json')

// anvil's first two well-known accounts.
const DEPLOYER = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const BOB = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
const PORT = 8547

let artifact: { bytecode: { object: `0x${string}` } } | null = null
try {
  artifact = JSON.parse(readFileSync(artifactPath, 'utf8'))
} catch {
  artifact = null
}

const describeOrSkip = artifact ? describe : describe.skip

describeOrSkip('generated builders against a deployed contract', () => {
  let anvil: ReturnType<typeof spawn>
  const account = privateKeyToAccount(DEPLOYER)
  const transport = http(`http://127.0.0.1:${PORT}`)
  const pub = createPublicClient({ chain: foundry, transport })
  const wallet = createWalletClient({ account, chain: foundry, transport })
  let wtia: `0x${string}`

  beforeAll(async () => {
    anvil = spawn('anvil', ['--silent', '--port', String(PORT)], { stdio: 'ignore' })
    // Poll rather than sleep: anvil is ready when it answers.
    for (let i = 0; i < 100; i++) {
      try {
        await pub.getChainId()
        break
      } catch {
        await new Promise((r) => setTimeout(r, 100))
      }
    }

    const hash = await wallet.deployContract({
      abi: wtia9Abi,
      bytecode: artifact!.bytecode.object,
    })
    const receipt = await pub.waitForTransactionReceipt({ hash })
    wtia = receipt.contractAddress!
  }, 60_000)

  afterAll(() => anvil?.kill())

  const balanceOf = (who: `0x${string}`) =>
    pub.readContract({ address: wtia, abi: wtia9Abi, functionName: 'balanceOf', args: [who] })

  it('sends value with a payable builder', async () => {
    const call = calls.wtia9.deposit(wtia, parseEther('2.5'))
    expect(call.value).toBe(parseEther('2.5'))

    const receipt = await pub.waitForTransactionReceipt({
      hash: await wallet.sendTransaction(call),
    })

    expect(receipt.status).toBe('success')
    expect(await balanceOf(account.address)).toBe(parseEther('2.5'))
  }, 60_000)

  it('passes arguments in order with a nonpayable builder', async () => {
    const call = calls.wtia9.transfer(wtia, BOB, parseEther('1'))
    expect(call.value).toBeUndefined()

    const receipt = await pub.waitForTransactionReceipt({
      hash: await wallet.sendTransaction(call),
    })

    expect(receipt.status).toBe('success')
    // Recipient and amount both landed where the ABI says they go.
    expect(await balanceOf(BOB)).toBe(parseEther('1'))
    expect(await balanceOf(account.address)).toBe(parseEther('1.5'))
  }, 60_000)
})
