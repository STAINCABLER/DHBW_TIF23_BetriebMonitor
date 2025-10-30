import { describe, expect, test } from 'vitest';
import { sanitizeIban, formatIbanForDisplay, normalizeAmountInput } from '../app.js';

describe('frontend helpers', () => {
  test('sanitizeIban removes whitespace and uppercases', () => {
    expect(sanitizeIban(' de12 3456 7890 1234 5678 90 ')).toBe('DE12345678901234567890');
    expect(sanitizeIban(null)).toBe('');
  });

  test('formatIbanForDisplay groups characters into blocks', () => {
    expect(formatIbanForDisplay('de89370400440532013000')).toBe('DE89 3704 0044 0532 0130 00');
    expect(formatIbanForDisplay('')).toBe('');
  });

  test('normalizeAmountInput enforces positive numbers', () => {
    expect(normalizeAmountInput('12,5')).toBe('12.50');
    expect(() => normalizeAmountInput('-1')).toThrow('Ungültiger Betrag.');
    expect(() => normalizeAmountInput('abc')).toThrow('Ungültiger Betrag.');
  });
});
