import {
  Component,
  DestroyRef,
  ElementRef,
  ViewEncapsulation,
  afterNextRender,
  effect,
  inject,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { Router } from '@angular/router';
import * as L from 'leaflet';

import { joinPresent } from '../../../core/format';
import { MapPoint } from '../../../core/models';

const WORLD_CENTER: L.LatLngTuple = [20, 0];
const MAX_ACCURACY_RING_KM = 250;

function severityColor(severity: string): string {
  if (severity === 'high') return '#ef4444';
  if (severity === 'medium') return '#f59e0b';
  return '#22c55e';
}

function formatAccuracy(radiusKm: number | null): string {
  const radius = Number(radiusKm);
  if (!Number.isFinite(radius) || radius <= 0) return 'Unknown';
  if (radius < 1) return '< 1 km';
  return radius >= 10 ? `${radius.toFixed(0)} km` : `${radius.toFixed(1)} km`;
}

@Component({
  selector: 'app-attack-map',
  styleUrl: './attack-map.css',
  templateUrl: './attack-map.html',
  // Leaflet builds popups outside Angular's view, so styles are unscoped and
  // every rule in attack-map.css is prefixed with the host selector instead.
  encapsulation: ViewEncapsulation.None,
})
export class AttackMap {
  /** null while the first request is in flight. */
  readonly points = input<MapPoint[] | null>(null);
  readonly failed = input(false);

  private readonly router = inject(Router);
  private readonly mapHost = viewChild.required<ElementRef<HTMLDivElement>>('mapHost');
  private readonly map = signal<L.Map | null>(null);
  private readonly markers = L.layerGroup();

  protected readonly status = signal('Loading map data and IP geolocation details...');

  constructor() {
    afterNextRender(() => {
      const map = L.map(this.mapHost().nativeElement, {
        zoomControl: true,
        attributionControl: true,
      }).setView(WORLD_CENTER, 2);

      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
      }).addTo(map);
      this.markers.addTo(map);

      // The container can still be settling its size on first paint.
      setTimeout(() => map.invalidateSize(), 100);
      this.map.set(map);
    });

    inject(DestroyRef).onDestroy(() => this.map()?.remove());

    effect(() => {
      const map = this.map();
      const points = this.points();
      if (!map || points === null) {
        return;
      }
      if (this.failed()) {
        this.markers.clearLayers();
        map.setView(WORLD_CENTER, 2);
        this.status.set('Map data is unavailable.');
        return;
      }
      this.render(map, points);
    });
  }

  private render(map: L.Map, points: MapPoint[]): void {
    this.markers.clearLayers();

    if (!points.length) {
      map.setView(WORLD_CENTER, 2);
      this.status.set('No public IP geolocation data is available yet.');
      return;
    }

    const bounds: L.LatLngTuple[] = [];
    for (const point of points) {
      const lat = Number(point.lat);
      const lon = Number(point.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
        continue;
      }

      const color = severityColor(point.severity);
      const radiusKm = Number(point.accuracy_radius_km);
      if (Number.isFinite(radiusKm) && radiusKm > 0) {
        L.circle([lat, lon], {
          radius: Math.min(radiusKm, MAX_ACCURACY_RING_KM) * 1000,
          color,
          fillColor: color,
          fillOpacity: 0.08,
          opacity: 0.3,
          weight: 1,
        }).addTo(this.markers);
      }

      L.circleMarker([lat, lon], {
        radius: 6,
        color,
        fillColor: color,
        fillOpacity: 0.85,
        weight: 1,
      })
        .bindPopup(() => this.buildPopup(point))
        .addTo(this.markers);
      bounds.push([lat, lon]);
    }

    if (!bounds.length) {
      map.setView(WORLD_CENTER, 2);
      this.status.set('Map data loaded but no valid coordinates available.');
      return;
    }

    if (bounds.length === 1) {
      map.setView(bounds[0], 4);
    } else {
      map.fitBounds(bounds, { padding: [30, 30] });
    }
    this.status.set(`Showing ${bounds.length} geolocated alert marker(s).`);
  }

  /** Popup built from DOM nodes (textContent only) so IP/ASN strings can't inject markup. */
  private buildPopup(point: MapPoint): HTMLElement {
    const popup = document.createElement('div');
    popup.className = 'map-popup';

    const line = (text: string, className?: string) => {
      const el = document.createElement('div');
      el.textContent = text;
      if (className) el.className = className;
      popup.append(el);
    };

    line(point.ip, 'map-popup__ip');
    line(
      `Location: ${joinPresent([point.city, point.subdivision, point.country]) || 'Unavailable'}`,
    );
    line(`Accuracy: ${formatAccuracy(point.accuracy_radius_km)}`);
    line(`Type: ${point.type}`);
    if (point.organization) {
      line(`Network: ${point.organization}`);
    }
    if (point.is_hosting_provider) {
      line('Hosted network (VPN/proxy/datacenter)', 'map-popup__hosted');
    }

    const link = document.createElement('a');
    link.href = 'alerts';
    link.className = 'map-popup__link';
    link.textContent = 'Open alerts';
    link.addEventListener('click', (event) => {
      event.preventDefault();
      void this.router.navigateByUrl('/alerts');
    });
    popup.append(link);
    return popup;
  }
}
