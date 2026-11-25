import { Link } from "react-router-dom";
import { useI18n } from "../i18n/index.js";

export default function NotFoundPage() {
  const { t, rich } = useI18n();
  return (
    <section>
      <h1>{t("notFound.title")}</h1>
      <p className="muted">{rich("notFound.text", { link: <Link to="/">{t("notFound.link")}</Link> })}</p>
    </section>
  );
}
