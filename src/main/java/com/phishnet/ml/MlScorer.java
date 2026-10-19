package com.phishnet.ml;

import com.phishnet.model.DomainAgeResult;
import com.phishnet.model.PhishNetConfig;
import com.phishnet.model.UrlAnalysisResult;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.OptionalDouble;

/**
 * The experimental ML layer as the scan path sees it: loads the trained model and
 * turns a URL's analysis results into a phishing probability.
 *
 * <p>It can never break a scan. {@link #open} handles every failure itself:
 * <ul>
 *   <li>No model file yet (first use): trains one from the bundled dataset and saves
 *       it; if saving fails, the freshly trained model is still used for this run.</li>
 *   <li>An unreadable or corrupt model file: prints one warning to stderr and returns
 *       a disabled scorer, so the scan carries on with no ML score.</li>
 * </ul>
 * A disabled scorer ({@code --no-ml}, or after a failure) returns empty for everything.
 */
public final class MlScorer {

    /** Default location: {@code ~/.phishnet/phishnet-model.json}, next to the scan history database. */
    public static final String DEFAULT_DIRECTORY = ".phishnet";
    public static final String DEFAULT_FILE_NAME = "phishnet-model.json";

    private static final MlScorer DISABLED = new MlScorer(null, null);

    private final MlModel model;
    private final FeatureExtractor extractor;

    private MlScorer(MlModel model, FeatureExtractor extractor) {
        this.model = model;
        this.extractor = extractor;
    }

    public static Path defaultPath() {
        String home = System.getProperty("user.home");
        Path base = home == null || home.isBlank() || home.equals("?") ? Path.of("") : Path.of(home);
        return base.resolve(DEFAULT_DIRECTORY).resolve(DEFAULT_FILE_NAME);
    }

    /** A scorer that never produces a probability ({@code --no-ml}). */
    public static MlScorer disabled() {
        return DISABLED;
    }

    /** Wraps an already-loaded model (for tests and callers that manage the file themselves). */
    public static MlScorer of(MlModel model, PhishNetConfig config) {
        return new MlScorer(model, new FeatureExtractor(config));
    }

    /**
     * Loads the model at {@code modelFile}, training and saving one from the bundled
     * dataset if the file doesn't exist yet. Never throws: problems are reported to
     * {@code err} and give back a {@link #disabled()} scorer.
     */
    public static MlScorer open(Path modelFile, PhishNetConfig config, PrintStream err) {
        if (!Files.exists(modelFile)) {
            return trainOnFirstUse(modelFile, config, err);
        }
        try {
            return of(MlModel.load(modelFile), config);
        } catch (IOException | RuntimeException e) {
            err.println("Warning: ML model " + modelFile + " could not be loaded (" + e.getMessage()
                    + "); skipping the ML score. Retrain it with: phishnet model train");
            return DISABLED;
        }
    }

    private static MlScorer trainOnFirstUse(Path modelFile, PhishNetConfig config, PrintStream err) {
        MlModel model;
        try {
            model = MlModel.train(TrainingData.bundled());
        } catch (IOException | RuntimeException e) {
            err.println("Warning: could not train the ML model from the bundled dataset ("
                    + e.getMessage() + "); skipping the ML score");
            return DISABLED;
        }
        try {
            model.save(modelFile);
        } catch (IOException | RuntimeException e) {
            err.println("Warning: could not save the ML model to " + modelFile + " (" + e.getMessage()
                    + "); it will be retrained on the next run");
        }
        return of(model, config);
    }

    public boolean isEnabled() {
        return model != null;
    }

    /** The loaded model, or {@code null} when disabled. */
    public MlModel model() {
        return model;
    }

    /** Phishing probability (0.0-1.0) for an already-extracted feature vector; empty when disabled. */
    public OptionalDouble probability(FeatureVector features) {
        return model == null ? OptionalDouble.empty() : OptionalDouble.of(model.probability(features));
    }

    /**
     * Extracts features from a scanned URL and scores them. Empty when disabled or
     * when the URL had no usable host (malformed input has nothing to classify).
     */
    public Optional<MlPrediction> predict(UrlAnalysisResult result, DomainAgeResult domainAge) {
        if (model == null || !FeatureExtractor.canExtract(result)) {
            return Optional.empty();
        }
        FeatureVector features = extractor.extract(result, domainAge);
        return Optional.of(new MlPrediction(model.probability(features), features));
    }
}
