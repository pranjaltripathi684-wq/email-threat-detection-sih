import React from 'react';
import { EmailDetail } from '../types';
import { GeoMap } from '../components/GeoMap';
import { Globe2, MapPin, Server, Shield } from 'lucide-react';

interface Props {
  email: EmailDetail | null;
}

export const GeolocationMapPage: React.FC<Props> = ({ email }) => {
  if (!email) {
    return (
      <div className="cyber-card p-10 text-center text-slate-500 italic">
        Please select an email to view geographic relay mapping.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
          <Globe2 className="w-5 h-5 text-cyan-400" />
          ESTIMATED GEOLOCATION & INFRASTRUCTURE MAP
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Interactive GIS mapping of intermediate public transmission servers and ASN routing points
        </p>
      </div>

      <div className="cyber-card p-6">
        <GeoMap hops={email.hops} earliestPublicIp={email.earliest_public_ip} />
      </div>

      {/* Geolocation Table */}
      <div className="cyber-card p-6">
        <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono mb-4 flex items-center gap-2">
          <MapPin className="w-4 h-4 text-cyan-400" />
          Geographic Coordinates & Hosting Telemetry
        </h3>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="p-3">Hop</th>
                <th className="p-3">Relay IP</th>
                <th className="p-3">Country / City</th>
                <th className="p-3">Coordinates (Lat / Lon)</th>
                <th className="p-3">Autonomous System (ASN / Org)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {email.hops
                .filter((h) => h.ip_classification === 'Public')
                .map((hop) => (
                  <tr key={hop.id} className="hover:bg-slate-800/20">
                    <td className="p-3 font-semibold text-slate-300 font-sans">
                      HOP #{hop.hop_order}
                    </td>
                    <td className="p-3 text-cyan-300 font-bold">{hop.extracted_ip}</td>
                    <td className="p-3 text-slate-200 font-sans">
                      {hop.geo_city && hop.geo_country ? `${hop.geo_city}, ${hop.geo_country}` : 'Unresolved'}
                    </td>
                    <td className="p-3 text-slate-400">
                      {hop.geo_lat && hop.geo_lon ? `${hop.geo_lat.toFixed(4)}, ${hop.geo_lon.toFixed(4)}` : '-'}
                    </td>
                    <td className="p-3 text-slate-300 font-sans">
                      {hop.asn_org || 'Standard Cloud / Relay Provider'}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
