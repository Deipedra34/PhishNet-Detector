import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <section>
      <h1>Page not found</h1>
      <p className="muted">
        There's nothing here. <Link to="/">Go to the scanner</Link>.
      </p>
    </section>
  );
}
