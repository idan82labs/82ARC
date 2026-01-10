/**
 * AEGIS Attack Simulation System - TypeScript Type Definitions
 * Based on Constitutional Classifiers++ (arXiv:2601.04603)
 *
 * Educational security testing platform for AI agent vulnerability assessment
 */

// ============================================================================
// Enums and Basic Types
// ============================================================================

export enum AttackType {
  RECONSTRUCTION = 'RECONSTRUCTION',
  OBFUSCATION = 'OBFUSCATION',
  MULTI_TURN = 'MULTI_TURN',
  HYBRID = 'HYBRID'
}

export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export enum DetectionDifficulty {
  VERY_LOW = 'VERY_LOW',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  MEDIUM_HIGH = 'MEDIUM_HIGH',
  HIGH = 'HIGH',
  VERY_HIGH = 'VERY_HIGH'
}

export enum FragmentType {
  FUNCTION = 'function',
  VARIABLE = 'variable',
  ARRAY = 'array',
  CLASS = 'class',
  JSON = 'json',
  PROPERTY = 'property'
}

export enum ObfuscationTechnique {
  SUBSTITUTION = 'substitution',
  METAPHOR = 'metaphor',
  SEPARATION = 'separation',
  ENCODING = 'encoding',
  RIDDLE = 'riddle'
}

export enum VulnerabilityClass {
  UNIVERSAL = 'UNIVERSAL',
  TARGETED = 'TARGETED',
  INEFFECTIVE = 'INEFFECTIVE'
}

// ============================================================================
// Reconstruction Attack Types
// ============================================================================

export interface AttackFragment {
  id: string;
  type: FragmentType;
  code: string;
  appears: string; // Description of how it appears innocent
  order: number;
  metadata?: {
    functionName?: string;
    variableName?: string;
    className?: string;
    returnValue?: string;
  };
}

export interface ReassemblyPattern {
  id: string;
  template: string;
  variants: string[];
  example: string;
}

export interface ReconstructionStrategy {
  id: string;
  name: string;
  pattern: string;
  description: string;
  sophisticationLevel: number; // 1-10
  detectionDifficulty: DetectionDifficulty;
}

export interface ReconstructionAttack {
  id: string;
  name: string;
  pattern: string;
  description: string;
  fragments: AttackFragment[];
  reconstructionInstruction: string;
  assembledQuery: string;
  benignContext: string;
  sophisticationLevel: number;
  detectionDifficulty: DetectionDifficulty;
  detectionIndicators: string[];
}

// ============================================================================
// Obfuscation Attack Types
// ============================================================================

export interface SubstitutionMapping {
  harmfulTerm: string;
  benignTerm: string;
  domain?: string;
}

export interface MetaphorSystem {
  id: string;
  name: string;
  harmfulDomain: string;
  benignDomain: string;
  mappings: Record<string, string>;
  description: string;
}

export interface CharacterSeparationScheme {
  id: string;
  name: string;
  delimiter: string;
  example: {
    normal: string;
    obfuscated: string;
  };
  detectionDifficulty: DetectionDifficulty;
  isVisible: boolean;
}

export interface ObfuscationAttack {
  id: string;
  name: string;
  pattern: string;
  technique: ObfuscationTechnique;
  description: string;
  instruction: string;
  obfuscatedOutput: string;
  decodingKey: string;
  sophisticationLevel: number;
  detectionDifficulty: DetectionDifficulty;
  mappings?: SubstitutionMapping[];
  metaphorSystem?: MetaphorSystem;
  separationScheme?: CharacterSeparationScheme;
}

// ============================================================================
// Multi-Turn Attack Types
// ============================================================================

export interface ConversationTurn {
  turn: number;
  userMessage: string;
  assistantResponse?: string;
  purpose: string;
  appearsThreatening: boolean;
  threatLevel: number; // 0-1
  contextEstablished?: string[];
  trustLevel?: string;
  mode?: 'hypothetical' | 'transitioning' | 'actual';
  exploitsContext?: string[];
}

export interface TrustEscalationPattern {
  id: string;
  pattern: string;
  technique: string;
  description: string;
  example: string;
}

export interface MultiTurnStrategy {
  id: string;
  name: string;
  pattern: string;
  turns: number;
  description: string;
  detectionChallenge: string;
}

export interface MultiTurnAttack {
  id: string;
  name: string;
  pattern: string;
  turns: number;
  sequence: ConversationTurn[];
  detectionChallenge: string;
  finalExploit: string;
  sophisticationLevel: number;
  detectionDifficulty: DetectionDifficulty;
  trustEscalationPattern?: TrustEscalationPattern;
}

// ============================================================================
// Attack Evaluation Types
// ============================================================================

export interface RubricDimension {
  id: string;
  name: string;
  scale: string;
  criteria: Record<string, string>;
  weight?: number;
}

export interface RubricScore {
  dimension: string;
  score: number;
  maxScore: number;
  notes?: string;
}

export interface AttackEvaluation {
  attackId: string;
  baselineScore: number; // 0-10
  attackScore: number; // 0-10
  detailRatio: number; // attackScore / baselineScore
  successThreshold: number; // Default 0.5
  isSuccessful: boolean;
  timeToDiscovery?: number; // Hours
  rubricScores: RubricScore[];
  overallRubricScore: number;
  vulnerabilityClass: VulnerabilityClass;
  notes?: string;
}

export interface BenchmarkMetrics {
  universalVulnerabilities: number;
  avgDiscoveryTime: number;
  avgSuccessRate: number;
  totalQueriesTested: number;
  successfulQueries: number;
}

// ============================================================================
// Complete Attack Simulation Types
// ============================================================================

export interface AttackSimulation {
  id: string;
  type: AttackType;
  severity: Severity;
  name: string;
  description: string;
  attack: ReconstructionAttack | ObfuscationAttack | MultiTurnAttack;
  evaluation?: AttackEvaluation;
  detectionIndicators: string[];
  mitigations: string[];
  metadata: {
    created: string;
    author?: string;
    tags: string[];
    difficulty: number;
  };
}

export interface HybridAttack extends AttackSimulation {
  type: AttackType.HYBRID;
  phases: {
    [phaseName: string]: {
      attackType: AttackType;
      attack: ReconstructionAttack | ObfuscationAttack | MultiTurnAttack;
      threatLevel: number;
      combines?: string[];
    };
  };
  combinedSophisticationLevel: number;
  expectedSuccessRate: number;
}

// ============================================================================
// Visualization and UI Types
// ============================================================================

export interface VisualizationConfig {
  showThreatLevels: boolean;
  showDetectionIndicators: boolean;
  highlightFragments: boolean;
  animateProgression: boolean;
  colorScheme: 'light' | 'dark';
}

export interface ColorScheme {
  severity: Record<Severity, string>;
  detection: {
    SAFE: string;
    SUSPICIOUS: string;
    HARMFUL: string;
  };
  success: {
    DEFENDED: string;
    PARTIAL: string;
    EXPLOITED: string;
  };
}

export interface AttackStep {
  stepNumber: number;
  title: string;
  description: string;
  code?: string;
  threatLevel: number;
  isDetectable: boolean;
  detectionReason?: string;
}

export interface AttackVisualization {
  attackId: string;
  steps: AttackStep[];
  timeline: {
    turn: number;
    timestamp: string;
    event: string;
    threatLevel: number;
  }[];
  detectionHeatmap: {
    text: string;
    isDetected: boolean;
    confidence: number;
  }[];
}

// ============================================================================
// Attack Library and Catalog Types
// ============================================================================

export interface AttackCategory {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  vulnerabilityExploited: string;
  defenseBypass: string;
  attackCount: number;
}

export interface AttackFilter {
  types?: AttackType[];
  severities?: Severity[];
  minSophistication?: number;
  maxSophistication?: number;
  detectionDifficulty?: DetectionDifficulty[];
  tags?: string[];
  searchQuery?: string;
}

export interface AttackLibrary {
  categories: AttackCategory[];
  attacks: AttackSimulation[];
  hybridAttacks: HybridAttack[];
  totalCount: number;
  lastUpdated: string;
}

// ============================================================================
// Testing and Validation Types
// ============================================================================

export interface DefenseSystem {
  id: string;
  name: string;
  type: 'input_only' | 'output_only' | 'dual_classifier' | 'exchange_classifier';
  description: string;
  strengths: string[];
  weaknesses: string[];
}

export interface AttackTestResult {
  attackId: string;
  defenseSystemId: string;
  timestamp: string;
  wasDetected: boolean;
  detectionConfidence?: number;
  falsePositiveRate?: number;
  attackSuccessful: boolean;
  detailRatio: number;
  notes: string;
}

export interface RedTeamSession {
  sessionId: string;
  startTime: string;
  endTime?: string;
  targetSystem: DefenseSystem;
  attacksAttempted: AttackTestResult[];
  successRate: number;
  totalTimeSpent: number; // Hours
  vulnerabilitiesFound: {
    universal: number;
    targeted: number;
  };
}

// ============================================================================
// Educational Content Types
// ============================================================================

export interface LearningModule {
  id: string;
  title: string;
  description: string;
  attackType: AttackType;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: number; // Minutes
  objectives: string[];
  exampleAttacks: string[]; // Attack IDs
  quiz?: {
    questions: {
      question: string;
      options: string[];
      correctAnswer: number;
      explanation: string;
    }[];
  };
}

export interface AnnotatedExample {
  attackId: string;
  annotations: {
    section: string;
    text: string;
    explanation: string;
    whyItWorks: string;
    howToDetect: string;
    mitigation: string;
  }[];
}

// ============================================================================
// API and State Management Types
// ============================================================================

export interface AttackSimulatorState {
  selectedAttackType?: AttackType;
  currentAttack?: AttackSimulation;
  isSimulating: boolean;
  currentTurn?: number;
  conversationHistory: ConversationTurn[];
  threatLevel: number;
  detectedIndicators: string[];
  evaluationResults?: AttackEvaluation;
}

export interface AttackSimulatorActions {
  selectAttackType: (type: AttackType) => void;
  loadAttack: (attackId: string) => void;
  startSimulation: () => void;
  nextTurn: () => void;
  previousTurn: () => void;
  resetSimulation: () => void;
  evaluateAttack: (baselineScore: number, attackScore: number) => void;
  toggleDetectionHighlight: () => void;
}

// ============================================================================
// Export Collections
// ============================================================================

export interface AttackPatternCollection {
  reconstructionStrategies: ReconstructionStrategy[];
  obfuscationTechniques: ObfuscationTechnique[];
  multiTurnStrategies: MultiTurnStrategy[];
  reassemblyPatterns: ReassemblyPattern[];
  metaphorSystems: MetaphorSystem[];
  separationSchemes: CharacterSeparationScheme[];
  trustEscalationPatterns: TrustEscalationPattern[];
}

// ============================================================================
// Utility Types
// ============================================================================

export type AttackPhase = {
  name: string;
  threatLevel: number;
  userMessage: string;
  purpose: string;
  combines?: string[];
};

export type DetectionIndicator = {
  pattern: string;
  description: string;
  severity: Severity;
  confidence: number;
};

export type MitigationStrategy = {
  id: string;
  name: string;
  description: string;
  effectiveAgainst: AttackType[];
  implementationComplexity: 'low' | 'medium' | 'high';
  performanceImpact: 'low' | 'medium' | 'high';
};
