import React, { useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import { Hop } from '../types';
import { ShieldAlert, Info } from 'lucide-react';

interface Props {
  hops: Hop[];
  earliestPublicIp?: string;
}

// Custom Leaflet pulse marker icon
const createCustomIcon = (isEarliest: boolean) => {
  return L.divIcon({
    className: 'custom-geo-marker',
    html: `
      <div style="
        width: 22px;
        height: 22px;
        background: ${isEarliest ? '#06b6d4' : '#3b82f6'};
        border: 2px solid white;
        border-radius: 50%;
        box-shadow: 0 0 15px ${isEarliest ? '#06b6d4' : '#3b82f6'};
        display: flex;
        align-items: center;
        justify-content: center;
        color: black;
        font-weight: bold;
        font-size: 11px;
      ">
        ${isEarliest ? '★' : '•'}
      </div>
    `,
    iconSize: [22, 22],
    iconAnchor: [11, 11],
  });
};

export const GeoMap: React.FC<Props> = ({ hops, earliestPublicIp }) => {
  const validHops = hops.filter((h) => h.geo_lat && h.geo_lon && (h.geo_lat !== 0 || h.geo_lon !== 0));

  const center: [number, number] = validHops.length > 0
    ? [validHops[0].geo_lat!, validHops[0].geo_lon!]
    : [30.0, 0.0];

  const polylineCoords = validHops.map((h) => [h.geo_lat!, h.geo_lon!] as [number, number]);

  return (
    <div className="space-y-4">
      {/* Attribution Disclaimer Banner */}
      <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-300 text-xs flex items-start gap-2.5">
        <Info className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
        <div>
          <span className="font-semibold uppercase tracking-wider font-mono">Defensive Attribution Notice: </span>
          Geolocation coordinates represent the estimated physical hosting location of the observed transmission servers. This does not prove the attacker was physically located in this region.
        </div>
      </div>

      <div className="h-[480px] w-full rounded-xl overflow-hidden border border-slate-800 relative z-0">
        <MapContainer
          center={center}
          zoom={validHops.length > 0 ? 3 : 2}
          style={{ height: '100%', width: '100%' }}
          scrollWheelZoom={false}
        >
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CartoDB</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />

          {validHops.map((hop, idx) => {
            const isEarliest = hop.is_earliest_reliable_public_ip || hop.extracted_ip === earliestPublicIp;
            return (
              <Marker
                key={hop.id || idx}
                position={[hop.geo_lat!, hop.geo_lon!]}
                icon={createCustomIcon(isEarliest)}
              >
                <Popup className="custom-leaflet-popup">
                  <div className="text-xs p-1 text-slate-900 font-sans">
                    <div className="font-bold text-sm text-cyan-700">
                      HOP #{hop.hop_order} {isEarliest && '(Earliest Public Relay)'}
                    </div>
                    <div className="mt-1 font-mono">
                      <strong>IP:</strong> {hop.extracted_ip}
                    </div>
                    <div>
                      <strong>Location:</strong> {hop.geo_city}, {hop.geo_country}
                    </div>
                    <div>
                      <strong>Infrastructure:</strong> {hop.asn_org || 'Unknown'}
                    </div>
                    <div>
                      <strong>TLS:</strong> {hop.tls_status ? 'Active' : 'Disabled'}
                    </div>
                  </div>
                </Popup>
              </Marker>
            );
          })}

          {polylineCoords.length > 1 && (
            <Polyline
              positions={polylineCoords}
              pathOptions={{ color: '#06b6d4', weight: 3, dashArray: '6, 8', opacity: 0.8 }}
            />
          )}
        </MapContainer>
      </div>
    </div>
  );
};
