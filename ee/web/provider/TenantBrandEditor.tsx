// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

import { useEffect, useState, type FormEvent } from "react";
import { Button, Field, TextArea } from "../../../web/src/components";
import { providerResponse } from "./providerData";
import styles from "./ProviderConsole.module.css";

type Brand = {
  name: string;
  domain?: string;
  logo_data_uri?: string;
  colors?: Record<string, string>;
};

function readLogo(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") resolve(reader.result);
      else reject(new Error("Could not read the PNG logo."));
    };
    reader.onerror = () => reject(new Error("Could not read the PNG logo."));
    reader.readAsDataURL(file);
  });
}

export function TenantBrandEditor({
  tenant,
  readOnly,
  onClose,
}: {
  tenant: { id: string; name: string };
  readOnly: boolean;
  onClose: () => void;
}) {
  const path = `/provider/v1/tenants/${encodeURIComponent(tenant.id)}/brand`;
  const [brand, setBrand] = useState<Brand>({ name: "" });
  const [palette, setPalette] = useState("{}");
  const [revision, setRevision] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    providerResponse("GET", path)
      .then(async (response) => {
        const loaded = (await response.json()) as Brand;
        const etag = response.headers.get("ETag");
        if (!etag) throw new Error("The saved brand has no revision.");
        if (cancelled) return;
        setBrand(loaded);
        setPalette(JSON.stringify(loaded.colors ?? {}, null, 2));
        setRevision(etag);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [path, attempt]);

  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!revision || readOnly || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const colors: unknown = JSON.parse(palette);
      if (
        !colors ||
        typeof colors !== "object" ||
        Array.isArray(colors) ||
        Object.values(colors).some((value) => typeof value !== "string")
      ) {
        throw new Error(
          "Use a JSON object of color tokens and plain HSL values.",
        );
      }
      const response = await providerResponse(
        "PUT",
        path,
        { ...brand, colors },
        { "If-Match": revision },
      );
      const saved = (await response.json()) as Brand;
      setRevision(response.headers.get("ETag") ?? "");
      setBrand(saved);
      setPalette(JSON.stringify(saved.colors ?? {}, null, 2));
      setMessage("Customer brand saved.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function chooseLogo(file?: File) {
    if (!file) return;
    if (file.type !== "image/png" || file.size > 32 * 1024) {
      setError("Choose a PNG of 32 KiB or less.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const logo = await readLogo(file);
      setBrand((previous) => ({ ...previous, logo_data_uri: logo }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const locked = busy || !revision || readOnly;
  return (
    <form
      className={styles.taskStack}
      onSubmit={save}
      aria-label={`Brand for ${tenant.name}`}
    >
      <h3>{tenant.name} brand</h3>
      <Field
        label="Product name"
        maxLength={120}
        value={brand.name}
        disabled={locked}
        onChange={(e) => setBrand({ ...brand, name: e.target.value })}
      />
      <Field
        label="Custom domain"
        maxLength={253}
        value={brand.domain ?? ""}
        disabled={locked}
        onChange={(e) => setBrand({ ...brand, domain: e.target.value })}
      />
      <Field
        label="Logo PNG"
        type="file"
        accept="image/png"
        disabled={locked}
        onChange={(e) => void chooseLogo(e.target.files?.[0])}
      />
      {brand.logo_data_uri ? (
        <Button
          type="button"
          disabled={locked}
          onClick={() => setBrand({ ...brand, logo_data_uri: "" })}
        >
          Remove logo
        </Button>
      ) : null}
      <TextArea
        label="Color overrides"
        value={palette}
        disabled={locked}
        onChange={(e) => setPalette(e.target.value)}
      />
      {error ? <p role="alert">{error}</p> : null}
      {message ? <p role="status">{message}</p> : null}
      <div className={styles.row}>
        <Button type="submit" variant="primary" disabled={locked}>
          Save brand
        </Button>
        <Button
          type="button"
          disabled={busy}
          onClick={() => {
            setError("");
            setMessage("");
            setRevision("");
            setBusy(true);
            setAttempt((current) => current + 1);
          }}
        >
          Reload saved brand
        </Button>
        <Button type="button" onClick={onClose}>
          Close brand editor
        </Button>
      </div>
    </form>
  );
}
