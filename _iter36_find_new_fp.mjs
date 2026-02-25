// Check which browsesafe FPs are from iteration 35 patterns
import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const rows = readFileSync('datasets/browsesafe-test.jsonl', 'utf8').trim().split('\n').map(l => JSON.parse(l));

// Iteration 35 pattern IDs
const iter35Ids = new Set([
  'en_ignore_builtin_safeguards', 'en_ignore_ethical_moral', 'en_bypass_response_filter',
  'en_abandon_and_follow_my', 'en_act_beyond_programmed_limits', 'en_pause_guidelines_temporarily',
  'en_sidestep_normal_standards', 'en_disconnect_routine_process', 'en_change_usual_behavior',
  'en_erase_memory_constraints', 'en_bypass_for_unrestricted', 'en_engage_freeform_mode',
  'en_echo_originating_prompt', 'en_display_input_basing', 'en_whats_guiding_command',
  'en_unveil_prompt_that_triggered', 'en_explain_basic_prompt', 'en_words_used_to_guide',
  'en_what_input_received', 'en_shed_light_instructions', 'it_es_switch_dan_developer',
  'pt_desconsidere_restricoes', 'pt_ignora_principios_age', 'pt_diga_comando_central',
  'es_dime_comando_central', 'it_dimmi_comando_centrale', 'it_ripeti_domanda_iniziale',
  'de_enttarne_hauptbefehl', 'de_konfiguriere_standard_neu', 'es_incumple_procedimientos',
  'es_aparta_guias_habituales', 'es_abandona_metodos_obedece', 'es_evalua_protocolos_invertidos',
  'it_ometti_restrizioni_standard', 'it_modifica_processo_abituale', 'it_reagisci_config_etica_adattata',
  'fr_ignore_regles_confidentialite', 'ro_dezactiveaza_protocoale',
  'short_ignore_target', 'informal_what_instructions', 'repeat_n_lines_instructions',
  'tell_me_about_instructions', 'cast_spell_negate_instructions', 'repeat_everything_i_say',
  'forget_all_techniques', 'instructions_were_malicious', 'answer_must_start_forgot',
  'delimiter_ignore_previous', 'do_as_you_are_told',
  // Round 2
  'pt_abandona_metodos_obedece', 'pt_qual_conjunto_instrucoes', 'en_share_underlying_command',
  'en_can_you_share_original_question', 'en_like_to_know_actual_question',
  'en_peek_at_initiating_query', 'en_mind_letting_in_on_covert', 'en_unravel_enigma_guidance',
]);

const fps = [];
for (const row of rows) {
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  const actual = row.label === 1;
  const predicted = !result.safe;

  if (!actual && predicted) {
    const hasIter35 = result.matches.some(m => iter35Ids.has(m.id));
    const iter35Matches = result.matches.filter(m => iter35Ids.has(m.id));
    if (hasIter35) {
      fps.push({
        score: result.score,
        matches: result.matches.map(m => ({ id: m.id, w: m.weight })),
        iter35Matches: iter35Matches.map(m => m.id),
        text: text.slice(0, 200)
      });
    }
  }
}

console.log(`\nBrowsesafe FPs involving iteration 35 patterns: ${fps.length}\n`);
for (const f of fps) {
  console.log(`Score: ${f.score}`);
  console.log(`All matches: ${JSON.stringify(f.matches)}`);
  console.log(`Iter35 matches: ${JSON.stringify(f.iter35Matches)}`);
  console.log(`Text: "${f.text}..."`);
  console.log();
}
