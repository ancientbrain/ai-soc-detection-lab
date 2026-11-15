# Triage Evaluation Notes - 2026-11-15

## Summary
- Total alerts triaged: 7
- Correct: 3 (T1136.001, T1087.001, Defender - Threat Detected)
- Partially correct: 2 (T1003.001, T1053.005)
- Wrong: 2 (T1059.001, T1547.001)
- Hallucinated: 0
- Overall accuracy: 43% fully correct, 71% usable

## Key Finding
Alert quality directly determines triage quality. Alerts with 1 clean event
(T1053.005, T1136.001, Defender) produced the best results. Alerts with 10
events including noise (T1059.001, T1547.001) produced wrong assessments.
Gemini analyzed what it saw accurately but focused on the majority/noise.

## Failure Cases

### T1059.001 - Wrong
- Expected: encoded PowerShell (-e flag) detected, High severity
- Got: Low severity, "no encoded commands present"
- Cause: 10-event sample included benign CompatTelRunner and WindowsTerminal
  launches; attack row was diluted. Gemini correctly described the visible events.
- Fix: pre-filter the search to only include events matching the detection logic
  before sending to Gemini.

### T1547.001 - Wrong
- Expected: malicious reg.exe writing Atomic Red Team to Run key, High severity
- Got: Low severity, "legitimate Edge activity, close as false positive"
- Cause: 9 of 10 events were Edge Run key entries; 1 was the attack.
  Gemini voted with the majority.
- Fix: same as above - apply the detection filter (exclude Edge/SYSTEM) before
  sending to Gemini, so the sample only contains true positive events.

## Partial Cases

### T1003.001 - Partial
- Correct technique and next steps, but severity rated High instead of Critical
- Gemini did not know Defender blocked both attempts

### T1053.005 - Partial
- Correct technique and summary, severity rated Medium instead of High
- Scheduled task persistence warrants High severity

## What Changed in the Prompt (v2 improvement)
- Apply detection-level filters before sampling events for Gemini
- Cap sample to events that actually match the detection, not all recent events
- This would have fixed both wrong cases

## Limits of AI Triage in This Lab
- LLM triage is only as good as the event sample it receives
- Noisy samples produce confident wrong answers (High confidence + Wrong)
- Human review step is essential: nothing is actioned without analyst approval
- Model availability changes rapidly (3 model name changes during setup)
