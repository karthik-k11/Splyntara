# Splyntara demo project

This directory is a small, self-contained project for trying Splyntara without
creating a dependency manifest from scratch. It contains only a valid
`requirements.txt` with two ordinary utility packages:

- `click`
- `colorama`

The manifest declares version constraints, not resolved versions. Discovery and
CycloneDX SBOM generation work fully offline. A vulnerability scan will report
both dependencies as unresolved and will not contact OSV, which is expected.

## Analyze with the dashboard

1. Start Splyntara from the repository root:

   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```

2. Open `http://127.0.0.1:5000/`.
3. Enter the absolute path to this directory, for example:

   ```text
   C:\path\to\Splyntara\examples\demo_project
   ```

4. Run the analysis. The dashboard shows two discovered dependencies and can
   generate a CycloneDX SBOM.

## Analyze with the API

From the repository root, resolve the demo path and call the discovery endpoint:

```powershell
$demo = (Resolve-Path .\examples\demo_project).Path

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:5000/api/dependencies/discover `
  -ContentType application/json `
  -Body (@{ project_directory = $demo } | ConvertTo-Json)
```

Generate an SBOM:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:5000/api/sbom/generate `
  -ContentType application/json `
  -Body (@{ project_directory = $demo } | ConvertTo-Json) `
  -OutFile demo-sbom.json
```

No live OSV request is required for either command.
