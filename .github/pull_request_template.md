# What & why

<!-- Closes #NNN. What changed and why. The body stays within 200 words outside
     one fenced block of verification output; the evidence lives in the issue. -->

## Checklist

- [ ] Security hardening / bug fix / feature / refactor or docs (keep one).
- [ ] Login path, crypto, config persistence or release pipeline: fail-closed
      preserved, no secret logged, a security review ran and its record (per
      lens the verdict, CONFIRMED / PLAUSIBLE counts, a disposition per finding)
      is here or linked.
- [ ] No duplicated logic, no more code than the problem requires, a new
      structural property locked in `ArchitectureConformanceTests`.
- [ ] Docs: README and wiki updated here, or a `documentation` issue linked.
- [ ] `dotnet build --no-restore --warnaserror`, `dotnet test` and Prettier green.

## Notes

<!-- Trade-offs, follow-ups, paths outside the issue's scope. -->
