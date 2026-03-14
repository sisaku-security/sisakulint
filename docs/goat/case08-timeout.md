+++
title = 'Case 08: Missing Timeout'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 8
+++

# Case 08: Missing Timeout

## Target Files

All 24 files (134 findings)

## Vulnerability Overview

When `timeout-minutes` is not set, GitHub Actions defaults to a 360-minute timeout. Attackers can exploit this to run cryptocurrency miners or cause resource exhaustion through infinite loops, consuming the repository's Actions usage quota.

## Auto-Fix

sisakulint can automatically add `timeout-minutes: 5` using `-fix on`.

## Verdict: DETECTED
