export function roundedCostCents(seconds, hourlyRateCents) {
  const numerator = BigInt(seconds) * BigInt(hourlyRateCents);
  return Number((numerator + 1800n) / 3600n);
}

export function sessionCostCents(seconds, hourlyRateCents) {
  return roundedCostCents(seconds, hourlyRateCents);
}

export function summarizeReportSessions(sessions, hourlyRateCents) {
  const rows = sessions.map((session) => ({
    ...session,
    costCents: sessionCostCents(session.seconds, hourlyRateCents),
  }));
  return {
    rows,
    seconds: rows.reduce((total, row) => total + row.seconds, 0),
    costCents: rows.reduce((total, row) => total + row.costCents, 0),
  };
}

export function shouldDeferLiveReplacement({ dirty, focused, openDisclosure }) {
  return dirty || focused || openDisclosure;
}

export function isDirtyLiveControl(control) {
  if (control.type === "hidden") return false;
  if (control.type === "checkbox" || control.type === "radio") {
    return control.checked !== control.defaultChecked;
  }
  if (control.tagName === "SELECT") {
    const options = Array.from(control.options);
    const defaults = options.map((option) => option.defaultSelected);
    if (!control.multiple && !defaults.some(Boolean)) {
      const first = options.findIndex((option) => !option.disabled);
      if (first >= 0) defaults[first] = true;
    }
    return options.some((option, index) => option.selected !== defaults[index]);
  }
  return control.value !== control.defaultValue;
}
