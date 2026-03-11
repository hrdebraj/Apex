import { create } from "zustand";
import { COMMAND_TO_MITRE, MITRE_TECHNIQUES, MitreTechnique } from "../services/mitreData";

export interface MitreEvent {
  id: string;
  techniqueId: string;
  technique: MitreTechnique;
  agentId: string;
  agentHostname: string;
  operatorId: string;
  command: string;
  timestamp: Date;
}

interface MitreState {
  events: MitreEvent[];
  addEvent: (agentId: string, agentHostname: string, operatorId: string, command: string) => void;
  clearEvents: () => void;
}

let eventCounter = 0;

export const useMitreStore = create<MitreState>((set) => ({
  events: [],

  addEvent: (agentId, agentHostname, operatorId, command) => {
    const baseCommand = command.split(" ")[0].toLowerCase();
    const techniqueIds = COMMAND_TO_MITRE[baseCommand];
    if (!techniqueIds) return;

    const newEvents: MitreEvent[] = techniqueIds
      .map((tid) => {
        const technique = MITRE_TECHNIQUES[tid];
        if (!technique) return null;
        return {
          id: `mitre-${++eventCounter}`,
          techniqueId: tid,
          technique,
          agentId,
          agentHostname,
          operatorId,
          command,
          timestamp: new Date(),
        };
      })
      .filter(Boolean) as MitreEvent[];

    set((state) => ({ events: [...state.events, ...newEvents] }));
  },

  clearEvents: () => set({ events: [] }),
}));
