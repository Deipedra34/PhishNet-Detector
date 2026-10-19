package com.phishnet.cli;

import com.phishnet.ml.FeatureVector;
import com.phishnet.ml.MlModel;
import com.phishnet.ml.MlScorer;
import com.phishnet.ml.TrainingData;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.Callable;

/**
 * {@code phishnet model train|info}: manages the experimental ML layer's model file
 * ({@link MlScorer}). Like {@code history}, {@link Main#run} hands it the arguments
 * after "model", so normal scan parsing is untouched.
 */
@Command(
        name = "phishnet " + Main.MODEL_COMMAND,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        synopsisSubcommandLabel = "COMMAND",
        description = "Train or inspect the experimental ML model that adds a phishing probability "
                + "(\"ML Confidence\") next to the rule-based risk score. Scans train it from the bundled "
                + "dataset automatically on first use; --no-ml turns it off for a scan.",
        synopsisHeading = "%nUsage:%n",
        descriptionHeading = "%n",
        optionListHeading = "%nOptions:%n",
        commandListHeading = "%nCommands:%n",
        footerHeading = "%nExamples:%n",
        footer = {
                "  phishnet model train",
                "  phishnet model train --data my-training-data.csv",
                "  phishnet model info"
        }
)
final class ModelCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        throw new ParameterException(spec.commandLine(), "Missing required command: train or info");
    }

    /** The {@code model} command with its subcommands wired to the given streams. */
    static CommandLine commandLine(PrintStream out, PrintStream err) {
        CommandLine cmd = new CommandLine(new ModelCommand());
        cmd.addSubcommand("train", new TrainCommand(out, err));
        cmd.addSubcommand("info", new InfoCommand(out, err));
        return cmd;
    }

    /** The {@code --model} option shared by both subcommands. */
    abstract static class ModelFileCommand implements Callable<Integer> {

        @Option(names = "--model", paramLabel = "<path>",
                description = "Model file (default: ~/.phishnet/phishnet-model.json)")
        String modelPath;

        final PrintStream out;
        final PrintStream err;

        ModelFileCommand(PrintStream out, PrintStream err) {
            this.out = out;
            this.err = err;
        }

        Path modelFile() {
            return modelPath != null ? Path.of(modelPath) : MlScorer.defaultPath();
        }

        /** Dataset, size, class balance, and training accuracy lines shared by train and info. */
        void printTrainingSummary(MlModel model) {
            out.println("Training data:     " + model.dataset());
            out.println("Dataset size:      " + model.datasetSize() + " examples ("
                    + model.phishingExamples() + " phishing, " + model.legitimateExamples() + " legitimate)");
            out.println("Training accuracy: " + percent(model.trainingAccuracy()));
        }
    }

    @Command(
            name = "train",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            description = "Train the model from the bundled dataset (or a CSV file of your own) and save it, "
                    + "replacing any existing model file.",
            synopsisHeading = "%nUsage:%n",
            descriptionHeading = "%n",
            optionListHeading = "%nOptions:%n"
    )
    static final class TrainCommand extends ModelFileCommand {

        @Option(names = "--data", paramLabel = "<path>",
                description = "Labeled training CSV to use instead of the bundled dataset "
                        + "(same columns as the bundled training-data.csv; label 1 = phishing, 0 = legitimate)")
        String dataPath;

        TrainCommand(PrintStream out, PrintStream err) {
            super(out, err);
        }

        @Override
        public Integer call() {
            TrainingData data;
            try {
                data = dataPath != null ? TrainingData.load(Path.of(dataPath)) : TrainingData.bundled();
            } catch (IOException | RuntimeException e) {
                String source = dataPath != null ? dataPath : TrainingData.BUNDLED_SOURCE;
                err.println("Error: could not load training data " + source + ": " + describe(e));
                return 1;
            }

            MlModel model = MlModel.train(data);
            Path file = modelFile();
            try {
                model.save(file);
            } catch (IOException | RuntimeException e) {
                err.println("Error: could not save the model to " + file + ": " + describe(e));
                return 1;
            }

            out.println("Trained a " + algorithmName(model) + " model on " + model.featureCount() + " features.");
            printTrainingSummary(model);
            out.println("Model saved to:    " + file);
            return 0;
        }
    }

    @Command(
            name = "info",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            description = "Show the current model: when and on what it was trained, and its learned weights.",
            synopsisHeading = "%nUsage:%n",
            descriptionHeading = "%n",
            optionListHeading = "%nOptions:%n"
    )
    static final class InfoCommand extends ModelFileCommand {

        InfoCommand(PrintStream out, PrintStream err) {
            super(out, err);
        }

        @Override
        public Integer call() {
            Path file = modelFile();
            if (!Files.exists(file)) {
                out.println("No trained model at " + file + " yet.");
                out.println("One is trained from the bundled dataset automatically on the first scan, "
                        + "or run: phishnet model train");
                return 0;
            }
            MlModel model;
            try {
                model = MlModel.load(file);
            } catch (IOException | RuntimeException e) {
                err.println("Error: could not read model file " + file + ": " + describe(e));
                err.println("Retrain it with: phishnet model train");
                return 1;
            }

            out.println("Model file:        " + file);
            out.println("Algorithm:         " + algorithmName(model));
            out.println("Trained:           " + model.trainedAt());
            printTrainingSummary(model);
            out.println("Features (" + model.featureCount() + "):");
            double[] weights = model.classifier().weights();
            for (int i = 0; i < weights.length; i++) {
                out.println(String.format(Locale.ROOT, "  %-16s %+.3f", FeatureVector.NAMES.get(i), weights[i]));
            }
            out.println(String.format(Locale.ROOT, "  %-16s %+.3f", "(bias)", model.classifier().bias()));
            out.println("Weights apply to standardized feature values: positive pushes toward phishing, "
                    + "negative toward legitimate.");
            return 0;
        }
    }

    private static String algorithmName(MlModel model) {
        return model.algorithm().replace('-', ' ');
    }

    private static String percent(double fraction) {
        return String.format(Locale.ROOT, "%.1f%%", fraction * 100);
    }

    /** An exception's message, readable even for the ones whose message is just a path or missing. */
    private static String describe(Exception e) {
        if (e instanceof NoSuchFileException) {
            return "file not found";
        }
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }
}
