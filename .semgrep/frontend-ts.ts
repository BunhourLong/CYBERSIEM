declare const el: HTMLElement;
declare const value: string;
declare const sanitizer: { bypassSecurityTrustHtml(v: string): unknown };
declare const marker: { bindPopup(v: unknown): unknown };

// ruleid: no-raw-html-sink
el.innerHTML = value;

// ruleid: no-raw-html-sink
el.insertAdjacentHTML('beforeend', value);

// ruleid: no-raw-html-sink
sanitizer.bypassSecurityTrustHtml(value);

// ruleid: no-raw-html-sink
marker.bindPopup("<b>alert</b>");

// ok: no-raw-html-sink
el.textContent = value;

// ok: no-raw-html-sink
marker.bindPopup(() => el);
