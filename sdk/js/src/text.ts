// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

/**
 * Trimming characters in linear time. A regular expression like /x+$/ backtracks
 * quadratically on a long run of x that is not at the end (CodeQL
 * js/polynomial-redos); these loops look at each character once.
 */

export function trimEnd(s: string, chars: string): string {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1] as string)) end--;
  return s.slice(0, end);
}

export function trimStart(s: string, chars: string): string {
  let start = 0;
  while (start < s.length && chars.includes(s[start] as string)) start++;
  return s.slice(start);
}

export function trim(s: string, chars: string): string {
  return trimStart(trimEnd(s, chars), chars);
}
