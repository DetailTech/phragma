import qrcode from "./vendor/qrcode-generator-2.0.4.mjs";

const DEFAULT_ERROR_CORRECTION = "M";
const DEFAULT_CELL_SIZE = 5;
const DEFAULT_MARGIN = 4;
const MAX_QR_PAYLOAD_BYTES = 1800;

export function qrCodePayloadBytes(text = "") {
  return new TextEncoder().encode(String(text || "")).length;
}

export function qrCodeCapacity(text = "", opts = {}) {
  const bytes = qrCodePayloadBytes(text);
  const maxBytes = Number(opts.maxBytes || MAX_QR_PAYLOAD_BYTES);
  return {
    bytes,
    maxBytes,
    ok: bytes > 0 && bytes <= maxBytes,
  };
}

export function qrCodeSvg(text = "", opts = {}) {
  const payload = String(text || "");
  const capacity = qrCodeCapacity(payload, opts);
  if (!capacity.ok) {
    throw new Error(capacity.bytes ? `QR payload is too large (${capacity.bytes}/${capacity.maxBytes} bytes).` : "QR payload is empty.");
  }
  const qr = qrcode(0, opts.errorCorrection || DEFAULT_ERROR_CORRECTION);
  qr.addData(payload, "Byte");
  qr.make();
  return qr.createSvgTag({
    cellSize: Number(opts.cellSize || DEFAULT_CELL_SIZE),
    margin: Number(opts.margin || DEFAULT_MARGIN),
    scalable: true,
    title: opts.title || "WireGuard enrollment QR code",
    alt: opts.alt || "QR code containing the WireGuard enrollment configuration.",
  });
}
