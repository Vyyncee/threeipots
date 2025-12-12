import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Activity, AlertTriangle, RefreshCw, FileText, Filter, Play, Square } from 'lucide-react';

const MODELS_CONFIG = [
  { 
    id: 'http', 
    name: 'HTTP', 
    filePath: '/result/HTTP.csv', 
    color: '#3b82f6' 
  },
  { 
    id: 'ssh/telent', 
    name: 'SHH / TELNET', 
    filePath: '/result/SSH_TELNET.csv', 
    color: '#10b981' 
  },
  { 
    id: 'raw', 
    name: 'RAW', 
    filePath: '/result/RAW.csv', 
    color: '#f59e0b' 
  },
  { 
    id: 'smtp', 
    name: 'SMTP', 
    filePath: '/result/SMTP.csv', 
    color: '#8b5cf6' 
  }
];

// Configuration du backend
const API_CONFIG = {
  detectionToggleEndpoint: '/api/toggle',
  detectionStatusEndpoint: '/api/status'
};

const REFRESH_INTERVAL_MS = 60000; // 1 minute
const MAX_ROWS_DISPLAYED = 50;

// ============================================================================
// CONSTANTES
// ============================================================================

const LABEL_ATTACK = 'attack';
const LABEL_NORMAL = 'normal';

const FILTER_OPTIONS = {
  ALL: 'all',
  ATTACKS: 'attacks',
  NORMAL: 'normal'
};

// ============================================================================
// UTILITAIRES
// ============================================================================

/**
 * Parse un fichier CSV et retourne un tableau d'objets avec les colonnes détectées
 * @param {string} csvText - Contenu du fichier CSV
 * @returns {Object} { data: Array, columns: Array }
 */
const parseCSV = (csvText) => {
  const lines = csvText.trim().split('\n');
  if (lines.length < 2) return { data: [], columns: [] };

  const columns = lines[0].split(',').map(h => h.trim());
  
  const data = lines.slice(1)
    .filter(line => line.trim())
    .map(line => {
      const values = line.split(',');
      return columns.reduce((obj, header, index) => {
        obj[header] = values[index]?.trim() || '';
        return obj;
      }, {});
    });

  return { data, columns };
};

/**
 * Calcule les statistiques à partir des données CSV
 * @param {Array<Object>} data - Données parsées du CSV
 * @returns {Object} Statistiques calculées
 */
const calculateStats = (data) => {
  if (!data || data.length === 0) {
    return {
      total: 0,
      attacks: 0,
      normal: 0,
      detectionRate: 0
    };
  }

  const attackCount = data.filter(row => row.label === LABEL_ATTACK).length;
  const normalCount = data.length - attackCount;
  const detectionRate = data.length > 0 
    ? ((attackCount / data.length) * 100).toFixed(2) 
    : 0;

  return {
    total: data.length,
    attacks: attackCount,
    normal: normalCount,
    detectionRate
  };
};

/**
 * Filtre les données selon le type demandé
 * @param {Array<Object>} data - Données à filtrer
 * @param {string} filterType - Type de filtre (all, attacks, normal)
 * @param {number} limit - Nombre maximum de lignes à retourner
 * @returns {Array<Object>} Données filtrées
 */
const filterData = (data, filterType, limit = MAX_ROWS_DISPLAYED) => {
  let filtered = data;

  if (filterType === FILTER_OPTIONS.ATTACKS) {
    filtered = data.filter(row => row.label === LABEL_ATTACK);
  } else if (filterType === FILTER_OPTIONS.NORMAL) {
    filtered = data.filter(row => row.label === LABEL_NORMAL);
  }

  return filtered.slice(0, limit);
};

// ============================================================================
// COMPOSANTS
// ============================================================================

/**
 * Composant Header avec titre et contrôles
 */
const Header = ({ detectionRunning, onToggleDetection, onRefresh }) => (
  <div className="flex items-center justify-between mb-6">
    <div className="flex items-center gap-3">
      <Shield className="w-10 h-10 text-blue-400" />
      <div>
        <h1 className="text-3xl font-bold">IDS 3IPots</h1>
        <p className="text-slate-400">Système de Détection d'Intrusion Multi-Protocoles</p>
      </div>
    </div>
    
    <div className="flex items-center gap-4">
      <button
        onClick={onRefresh}
        className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
        aria-label="Rafraîchir les données"
      >
        <RefreshCw className="w-4 h-4" />
        Rafraîchir
      </button>
      
      <button
        onClick={onToggleDetection}
        className={`flex items-center gap-2 px-6 py-2 rounded-lg font-semibold transition-colors ${
          detectionRunning 
            ? 'bg-red-600 hover:bg-red-700' 
            : 'bg-green-600 hover:bg-green-700'
        }`}
        aria-label={detectionRunning ? 'Arrêter la détection' : 'Lancer la détection'}
      >
        {detectionRunning ? (
          <>
            <Square className="w-4 h-4" />
            Arrêter Détection
          </>
        ) : (
          <>
            <Play className="w-4 h-4" />
            Lancer Détection
          </>
        )}
      </button>
    </div>
  </div>
);

/**
 * Composant barre de statut
 */
const StatusBar = ({ detectionRunning, lastUpdate }) => (
  <div className="flex items-center justify-between bg-slate-800 border border-slate-700 rounded-lg p-4">
    <div className="flex items-center gap-3">
      <Activity 
        className={`w-5 h-5 ${detectionRunning ? 'text-green-400 animate-pulse' : 'text-slate-500'}`} 
      />
      <span className="font-medium">
        Statut: <span className={detectionRunning ? 'text-green-400' : 'text-slate-400'}>
          {detectionRunning ? 'En cours d\'analyse' : 'Arrêté'}
        </span>
      </span>
    </div>
    <div className="text-sm text-slate-400">
      Dernière mise à jour: {lastUpdate.toLocaleTimeString('fr-FR')}
    </div>
  </div>
);

/**
 * Composant onglets de sélection de protocole
 */
const ProtocolTabs = ({ protocols, selectedProtocol, onSelectProtocol }) => (
  <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
    {protocols.map(protocol => (
      <button
        key={protocol.id}
        onClick={() => onSelectProtocol(protocol.id)}
        className={`px-6 py-3 rounded-lg font-medium transition-colors whitespace-nowrap ${
          selectedProtocol === protocol.id
            ? 'text-white shadow-lg'
            : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
        }`}
        style={selectedProtocol === protocol.id ? { backgroundColor: protocol.color } : {}}
        aria-label={`Sélectionner le protocole ${protocol.name}`}
        aria-pressed={selectedProtocol === protocol.id}
      >
        {protocol.name}
      </button>
    ))}
  </div>
);

/**
 * Composant carte statistique
 */
const StatCard = ({ title, value, icon: Icon, iconColor, borderColor }) => (
  <div className={`bg-slate-800 border rounded-lg p-6 ${borderColor || 'border-slate-700'}`}>
    <div className="flex items-center justify-between mb-2">
      <span className="text-slate-400">{title}</span>
      <Icon className={`w-5 h-5 ${iconColor}`} />
    </div>
    <div className={`text-3xl font-bold ${iconColor}`}>{value}</div>
  </div>
);

/**
 * Composant filtres du tableau
 */
const TableFilters = ({ currentFilter, onFilterChange, stats }) => (
  <div className="flex items-center gap-3 mb-4">
    <Filter className="w-5 h-5 text-slate-400" />
    <span className="text-slate-400 font-medium">Afficher:</span>
    
    <button
      onClick={() => onFilterChange(FILTER_OPTIONS.ALL)}
      className={`px-4 py-2 rounded-lg font-medium transition-colors ${
        currentFilter === FILTER_OPTIONS.ALL
          ? 'bg-blue-600 text-white'
          : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
      }`}
    >
      Tous ({stats.total})
    </button>
    
    <button
      onClick={() => onFilterChange(FILTER_OPTIONS.ATTACKS)}
      className={`px-4 py-2 rounded-lg font-medium transition-colors ${
        currentFilter === FILTER_OPTIONS.ATTACKS
          ? 'bg-red-600 text-white'
          : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
      }`}
    >
      Attaques ({stats.attacks})
    </button>
    
    <button
      onClick={() => onFilterChange(FILTER_OPTIONS.NORMAL)}
      className={`px-4 py-2 rounded-lg font-medium transition-colors ${
        currentFilter === FILTER_OPTIONS.NORMAL
          ? 'bg-green-600 text-white'
          : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
      }`}
    >
      Normal ({stats.normal})
    </button>
  </div>
);

/**
 * Composant tableau dynamique basé sur les colonnes du CSV
 */
const DataTable = ({ rows, columns, protocol }) => {
  const displayColumns = columns.filter(col => col !== 'label');

  /**
   * Formatte une valeur de cellule pour l'affichage
   */
  const formatCellValue = (value, column) => {
    if (column === 'timestamp' && value) {
      try {
        return new Date(value).toLocaleString('fr-FR');
      } catch {
        return value;
      }
    }
    return value || 'N/A';
  };

  /**
   * Retourne le style de badge selon le label
   */
  const getLabelBadge = (label) => {
    if (label === LABEL_ATTACK) {
      return (
        <span className="px-3 py-1 text-xs font-medium bg-red-900/50 text-red-300 rounded-full">
          ATTAQUE
        </span>
      );
    }
    return (
      <span className="px-3 py-1 text-xs font-medium bg-green-900/50 text-green-300 rounded-full">
        NORMAL
      </span>
    );
  };

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
      <div className="p-6 border-b border-slate-700">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          Données Détectées - {protocol.toUpperCase()}
        </h2>
      </div>
      
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-slate-900">
            <tr>
              {displayColumns.map(column => (
                <th 
                  key={column}
                  className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider"
                >
                  {column.replace(/_/g, ' ')}
                </th>
              ))}
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Statut
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700">
            {rows.length === 0 ? (
              <tr>
                <td colSpan={displayColumns.length + 1} className="px-6 py-8 text-center text-slate-400">
                  Aucune donnée à afficher
                </td>
              </tr>
            ) : (
              rows.map((row, idx) => (
                <tr 
                  key={idx} 
                  className={`hover:bg-slate-700/50 transition-colors ${
                    row.label === LABEL_ATTACK ? 'bg-red-900/10' : ''
                  }`}
                >
                  {displayColumns.map(column => (
                    <td 
                      key={column}
                      className="px-6 py-4 text-sm text-slate-300"
                    >
                      {formatCellValue(row[column], column)}
                    </td>
                  ))}
                  <td className="px-6 py-4">
                    {getLabelBadge(row.label)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ============================================================================
// COMPOSANT PRINCIPAL
// ============================================================================

const App = () => {
  const [detectionRunning, setDetectionRunning] = useState(false);
  const [selectedProtocol, setSelectedProtocol] = useState(MODELS_CONFIG[0].id);
  const [stats, setStats] = useState({});
  const [protocolData, setProtocolData] = useState({});
  const [columns, setColumns] = useState({});
  const [filter, setFilter] = useState(FILTER_OPTIONS.ALL);
  const [lastUpdate, setLastUpdate] = useState(new Date());

  /**
   * Charge les données CSV pour un protocole donné
   */
  const loadCSVData = useCallback(async (protocolId) => {
    const config = MODELS_CONFIG.find(m => m.id === protocolId);
    if (!config) return;

    try {
      const response = await fetch(config.filePath);
      
      if (!response.ok) {
        throw new Error(`Erreur HTTP: ${response.status}`);
      }
      
      const csvText = await response.text();
      const { data, columns: csvColumns } = parseCSV(csvText);
      
      const calculatedStats = calculateStats(data);
      
      setStats(prev => ({
        ...prev,
        [protocolId]: calculatedStats
      }));

      setProtocolData(prev => ({
        ...prev,
        [protocolId]: data
      }));

      setColumns(prev => ({
        ...prev,
        [protocolId]: csvColumns
      }));
    } catch (error) {
      console.error(`Erreur lors du chargement des données pour ${protocolId}:`, error);
      
      setStats(prev => ({
        ...prev,
        [protocolId]: { total: 0, attacks: 0, normal: 0, detectionRate: 0 }
      }));
      
      setProtocolData(prev => ({
        ...prev,
        [protocolId]: []
      }));
      
      setColumns(prev => ({
        ...prev,
        [protocolId]: []
      }));
    }
  }, []);

  /**
   * Rafraîchit toutes les données
   */
  const refreshAllData = useCallback(() => {
    MODELS_CONFIG.forEach(model => loadCSVData(model.id));
    setLastUpdate(new Date());
  }, [loadCSVData]);

  /**
   * Bascule l'état de la détection
   */
  const toggleDetection = useCallback(async () => {
    try {
      const response = await fetch(API_CONFIG.detectionToggleEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setDetectionRunning(data.status === 'running');
      } else {
        console.error('Erreur lors du basculement de la détection');
        setDetectionRunning(prev => !prev);
      }
    } catch (error) {
      console.error('Erreur de connexion à l\'API:', error);
      setDetectionRunning(prev => !prev);
    }
  }, []);

  /**
   * Vérifie le statut de la détection au chargement
   */
  const checkDetectionStatus = useCallback(async () => {
    try {
      const response = await fetch(API_CONFIG.detectionStatusEndpoint);
      
      if (response.ok) {
        const data = await response.json();
        setDetectionRunning(data.running === true);
      }
    } catch (error) {
      console.error('Erreur lors de la vérification du statut:', error);
    }
  }, []);

  useEffect(() => {
    refreshAllData();
    checkDetectionStatus();
  }, [refreshAllData, checkDetectionStatus]);

  useEffect(() => {
    if (!detectionRunning) return;

    const intervalId = setInterval(() => {
      refreshAllData();
    }, REFRESH_INTERVAL_MS);

    return () => clearInterval(intervalId);
  }, [detectionRunning, refreshAllData]);

  useEffect(() => {
    setFilter(FILTER_OPTIONS.ALL);
  }, [selectedProtocol]);

  const currentStats = stats[selectedProtocol] || {
    total: 0,
    attacks: 0,
    normal: 0,
    detectionRate: 0
  };

  const currentData = protocolData[selectedProtocol] || [];
  const currentColumns = columns[selectedProtocol] || [];
  const filteredRows = filterData(currentData, filter);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      <div className="max-w-7xl mx-auto mb-8">
        <Header 
          detectionRunning={detectionRunning}
          onToggleDetection={toggleDetection}
          onRefresh={refreshAllData}
        />
        
        <StatusBar 
          detectionRunning={detectionRunning}
          lastUpdate={lastUpdate}
        />
      </div>

      <div className="max-w-7xl mx-auto">
        <ProtocolTabs 
          protocols={MODELS_CONFIG}
          selectedProtocol={selectedProtocol}
          onSelectProtocol={setSelectedProtocol}
        />

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <StatCard 
            title="Total Prédictions"
            value={currentStats.total}
            icon={FileText}
            iconColor="text-blue-400"
          />
          
          <StatCard 
            title="Attaques Détectées"
            value={currentStats.attacks}
            icon={AlertTriangle}
            iconColor="text-red-400"
            borderColor="border-red-900/50"
          />
          
          <StatCard 
            title="Trafic Normal"
            value={currentStats.normal}
            icon={Shield}
            iconColor="text-green-400"
            borderColor="border-green-900/50"
          />
          
          <StatCard 
            title="Taux Détection"
            value={`${currentStats.detectionRate}%`}
            icon={Activity}
            iconColor="text-purple-400"
          />
        </div>

        <TableFilters 
          currentFilter={filter}
          onFilterChange={setFilter}
          stats={currentStats}
        />

        <DataTable 
          rows={filteredRows}
          columns={currentColumns}
          protocol={selectedProtocol}
        />
      </div>
    </div>
  );
};

export default App;