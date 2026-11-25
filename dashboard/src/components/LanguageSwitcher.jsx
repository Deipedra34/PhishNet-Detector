import { LANGUAGES, LANGUAGE_NAMES, useI18n } from "../i18n/index.js";

/**
 * The header's language picker. The choice is remembered in this browser (next to
 * the API settings) and also asks the API for its messages in that language.
 */
export default function LanguageSwitcher() {
  const { language, setLanguage, t } = useI18n();
  return (
    <label className="language-switcher">
      <span className="visually-hidden">{t("language.label")}</span>
      <select value={language} onChange={(event) => setLanguage(event.target.value)}>
        {LANGUAGES.map((code) => (
          <option key={code} value={code} lang={code}>
            {LANGUAGE_NAMES[code]}
          </option>
        ))}
      </select>
    </label>
  );
}
