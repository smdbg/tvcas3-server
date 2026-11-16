/* Run with node tests/cards_ui_test.cjs. No browser or service credentials. */
const assert = require('node:assert/strict');
const {maskToBits,bitsToMask,parseUTC,utcInput,addMonth} = require('../tvcas/static/cards.js');
for (const value of ['00000000','00000001','80000000','80000001','FFFFFFFF','11111111','ABCDEF12']) {
  assert.equal(bitsToMask(maskToBits(value)), value);
}
assert.equal(maskToBits('80000000')[31], true);
assert.equal(maskToBits('80000000').filter(Boolean).length, 1);
assert.equal(maskToBits('00000001')[0], true);
assert.equal(bitsToMask(Array(32).fill(true)), 'FFFFFFFF');
for (const value of ['','0','fffffffff','0000000G','-0000001']) assert.equal(maskToBits(value), null);
assert.equal(addMonth('2024-01-31T22:57:45'), '2024-02-29T22:57:45');
assert.equal(addMonth('2025-01-31T22:57:45'), '2025-02-28T22:57:45');
assert.equal(addMonth('2026-12-31T23:59:59'), '2027-01-31T23:59:59');
assert.equal(addMonth('2026-03-29T01:30:00'), '2026-04-29T01:30:00');
assert.equal(addMonth('2026-02-31T12:30:45'), null);
assert.equal(addMonth('bad'), null);
assert.equal(addMonth('', new Date('2026-11-15T13:04:05Z')), '2026-12-15T13:04:05');
assert.equal(utcInput(parseUTC('2026-11-15T13:04')), '2026-11-15T13:04:00');
assert.equal(utcInput(new Date('2026-11-15T15:04:05+02:00')), '2026-11-15T13:04:05');
console.log('Card UI helpers: unsigned masks, UTC preservation and calendar-month arithmetic passed.');
