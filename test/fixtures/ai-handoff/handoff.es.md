<!-- probectl-ai-handoff/v1; lang=es; dir=ltr -->
# Entrega de investigación de Ask de probectl

> **Nota de investigación puntual y no autoritativa\. Este archivo es una copia local de una respuesta limitada por tenant y RBAC\. La evidencia puede envejecer, los permisos pueden cambiar y los registros de origen pueden conservarse o eliminarse\. Vuelve a abrir probectl y autoriza de nuevo cada fuente citada antes de tomar una decisión\.**

## Recibo

- **Contrato:** ` probectl-ai-handoff/v1 `
- **ID de respuesta:** ` ans/incident #42 `
- **Tenant:** ` tenant-acme `
- **Pregunta:** Why did checkout \*slow\* after \[change\]?
- **Confianza:** ` high `
- **Evidencia insuficiente:** no
- **Ruta de respaldo degradada:** sí
- **Modelo:** ` builtin `
- **Adaptador de razonamiento:** ` builtin `
- **Ejecución del razonamiento:** ` builtin_fallback `
- **Consentimiento de salida:** ` granted `
- **Adaptador intentado:** ` openai:operator-model `
- **Afirmaciones causales suprimidas:** 1

## Causa raíz fundamentada

> A BGP route change diverted checkout traffic through a congested transit\.

- **Citas:** [E1](#evidence-1)

## Hallazgos fundamentados

1. The route changed before latency rose\.
   - **Citas:** [E1](#evidence-1), [E2](#evidence-3)
2. Checkout latency crossed the warning threshold\.
   - **Citas:** [E2](#evidence-3)

## Plan de investigación de solo lectura

1. Check the exact incident and its correlated signals\.
   - **Dominio:** ` entities `
   - **Estado:** ` queried `
   - **Solo lectura:** sí
   - **Límite:** 50
   - **Cantidad de evidencias:** 2
   - **Truncado:** no
   - **Selector:** ` {"incident_id":"inc-42","target":"checkout.example"} `
   - **Nodo:** ` service:checkout `
   - **Ventana:** ` 2026-07-28T08:00:00Z — 2026-07-28T09:00:00Z `
2. Check change and routing events near the selected window\.
   - **Dominio:** ` events `
   - **Estado:** ` blocked `
   - **Solo lectura:** sí
   - **Límite:** 50
   - **Cantidad de evidencias:** 0
   - **Truncado:** no
   - **Motivo:** RBAC denied this read\.
3. Check bounded service metrics\.
   - **Dominio:** ` metrics `
   - **Estado:** ` skipped `
   - **Solo lectura:** sí
   - **Límite:** 25
   - **Cantidad de evidencias:** 0
   - **Truncado:** sí
   - **Motivo:** The source is not configured\.

## Evidencia por plano

### bgp

<a id="evidence-1"></a>
#### E1 — Route changed for 192\.0\.2\.0/24

- **Dominio:** ` entities `
- **Estado:** ` critical `
- **Ocurrió en:** ` 2026-07-28T08:15:00Z `
- **Fuente:** ` bgp://event/route-42 `
- **Resumen:** AS64501 announced a more\-specific route\.
- **Citado por:** causa raíz, hallazgo 1
- **Campos:** ` {"as_path":[64500,64501],"origin_asn":64501,"prefix":"192.0.2.0/24"} `

### change

<a id="evidence-2"></a>
#### E3 — Deployment completed

- **Dominio:** ` events `
- **Ocurrió en:** ` 2026-07-28T08:10:00Z `
- **Fuente:** no registrado
- **Resumen:** The application deployment completed without an error\.
- **Citado por:** no registrado
- **Campos:** ` {"deployment":"checkout-2026-07-28.1","status":"succeeded"} `

### metrics

<a id="evidence-3"></a>
#### E2 — Checkout p95 latency

- **Dominio:** ` metrics `
- **Estado:** ` warning `
- **Ocurrió en:** ` 2026-07-28T08:17:30.123Z `
- **Fuente:** ` metric://checkout/p95 `
- **Resumen:** p95 reached 940 ms &amp; remained elevated\.
- **Citado por:** hallazgo 1, hallazgo 2
- **Campos:** ` {"labels":{"service":"checkout","site":"blr-1"},"unit":"ms","value":940} `

## Limitaciones

> **Esta entrega es evidencia, no estado autoritativo en vivo, aprobación de remediación ni permiso para actuar\. Valida la telemetría, la autorización y el contexto operativo actuales en probectl\.**
