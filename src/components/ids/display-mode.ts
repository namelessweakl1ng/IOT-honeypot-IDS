/** Shared presentation-only display mode type.
 *
 * The backend has exactly EMPTY/DEMO/LIVE as runtime modes.
 * UNKNOWN is a presentation-only state meaning the backend mode
 * could not currently be verified. UNKNOWN must NEVER enter
 * runtime-mode transitions, scheduler logic, or materialization.
 */
export type DisplayMode = 'EMPTY' | 'DEMO' | 'LIVE' | 'UNKNOWN'
