import { useState, useEffect, useCallback } from 'react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from './useNyxEvents';

export interface Skill {
  name: string;
  category?: string;
  description?: string;
  technology?: string[];
  required_tools?: string[];
  execution_class?: string;
  path?: string;
}

export interface SkillStats {
  skill_count: number;
  count: number;
  categories: Record<string, number>;
}

export interface SkillFetchResult {
  skills: Skill[];
  count: number;
  categories: Record<string, number>;
}

// Module-level shared cache to prevent redundant fetches and ensure all components stay synchronized
let globalSkillsCache: Skill[] | null = null;
let globalSkillCount: number | null = null;
let globalCategoriesCache: Record<string, number> | null = null;
let globalFetchPromise: Promise<SkillFetchResult> | null = null;
const listeners = new Set<() => void>();

function notifyListeners() {
  listeners.forEach((callback) => {
    try { callback(); } catch {}
  });
}

function deriveCategories(skillsList: Skill[]): Record<string, number> {
  const cats: Record<string, number> = {};
  if (Array.isArray(skillsList)) {
    for (const s of skillsList) {
      const c = (s.category && typeof s.category === 'string') ? s.category.trim() : 'general';
      cats[c] = (cats[c] || 0) + 1;
    }
  }
  return cats;
}

async function fetchAuthoritativeSkills(forceRefresh = false): Promise<SkillFetchResult> {
  if (!forceRefresh && globalSkillsCache !== null && globalSkillCount !== null && globalCategoriesCache !== null) {
    return {
      skills: globalSkillsCache,
      count: globalSkillCount,
      categories: globalCategoriesCache,
    };
  }

  if (globalFetchPromise && !forceRefresh) {
    return globalFetchPromise;
  }

  globalFetchPromise = (async () => {
    try {
      // 1. Fetch live skills from backend
      const res = await fetchApi<any>('/api/v1/skills');
      const list = res?.data?.skills || res?.skills || [];
      const parsedCount = typeof res?.data?.skill_count === 'number' 
        ? res.data.skill_count 
        : typeof res?.data?.count === 'number' 
          ? res.data.count 
          : (Array.isArray(list) ? list.length : 0);

      if (Array.isArray(list) && list.length > 0) {
        globalSkillsCache = list;
        globalSkillCount = parsedCount || list.length;
        if (res?.data?.categories && typeof res.data.categories === 'object') {
          globalCategoriesCache = res.data.categories;
        } else {
          globalCategoriesCache = deriveCategories(list);
        }
      } else {
        // Fallback to stats endpoint
        const statsRes = await fetchApi<any>('/api/v1/skills/stats');
        const count = statsRes?.data?.skill_count ?? statsRes?.data?.count ?? statsRes?.skill_count ?? null;
        if (count !== null) {
          globalSkillCount = count;
        }
        if (statsRes?.data?.categories && typeof statsRes.data.categories === 'object') {
          globalCategoriesCache = statsRes.data.categories;
        }
      }
    } catch {
      // If full list failed, attempt lightweight health check
      try {
        const healthRes = await fetchApi<any>('/api/v1/health');
        if (typeof healthRes?.data?.skills_count === 'number') {
          globalSkillCount = healthRes.data.skills_count;
        } else if (typeof healthRes?.skills_count === 'number') {
          globalSkillCount = healthRes.skills_count;
        }
      } catch {}
    } finally {
      if (!globalCategoriesCache) {
        globalCategoriesCache = deriveCategories(globalSkillsCache || []);
      }
      globalFetchPromise = null;
      notifyListeners();
    }

    return {
      skills: globalSkillsCache || [],
      count: globalSkillCount ?? (globalSkillsCache?.length || 0),
      categories: globalCategoriesCache || {},
    };
  })();

  return globalFetchPromise;
}

export function useSkills() {
  const [skills, setSkills] = useState<Skill[]>(globalSkillsCache || []);
  const [skillCount, setSkillCount] = useState<number | null>(globalSkillCount);
  const [categories, setCategories] = useState<Record<string, number>>(globalCategoriesCache || {});
  const [loading, setLoading] = useState<boolean>(globalSkillCount === null);
  const [error, setError] = useState<string | null>(null);
  const { lastEvent } = useNyxEvents();

  const syncFromCache = useCallback(() => {
    setSkills(globalSkillsCache || []);
    setSkillCount(globalSkillCount);
    setCategories(globalCategoriesCache || deriveCategories(globalSkillsCache || []));
    if (globalSkillCount !== null) {
      setLoading(false);
    }
  }, []);

  const refreshSkills = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchAuthoritativeSkills(true);
      setSkills(res.skills);
      setSkillCount(res.count);
      setCategories(res.categories || deriveCategories(res.skills));
    } catch (err: any) {
      setError(err?.message || 'Failed to load skill inventory');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    listeners.add(syncFromCache);
    if (globalSkillCount === null) {
      fetchAuthoritativeSkills(false).then((res) => {
        setSkills(res.skills);
        setSkillCount(res.count);
        setCategories(res.categories || deriveCategories(res.skills));
        setLoading(false);
      }).catch((err) => {
        setError(err?.message || 'Failed to load skills');
        setLoading(false);
      });
    } else {
      syncFromCache();
    }

    return () => {
      listeners.delete(syncFromCache);
    };
  }, [syncFromCache]);

  // Refetch when relevant real-time events fire
  useEffect(() => {
    if (lastEvent?.event === 'skills_updated' || lastEvent?.event === 'recon_completed' || lastEvent?.event === 'mission_started') {
      refreshSkills();
    }
  }, [lastEvent, refreshSkills]);

  return {
    skills,
    count: skillCount ?? (skills.length || 0),
    skillCount: skillCount ?? (skills.length || 0),
    categories: categories || {},
    loading,
    error,
    refreshSkills,
  };
}

export default useSkills;
