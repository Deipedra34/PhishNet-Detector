package com.phishnet.cli;

import com.phishnet.i18n.Messages;
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
        resourceBundle = Main.MESSAGES_BUNDLE,
        mixinStandardHelpOptions = true,
        versionProvider = Main.VersionProvider.class,
        sortOptions = false,
        descriptionHeading = "%n")
final class ModelCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        throw new ParameterException(spec.commandLine(), Messages.text("cli.missingCommand.two", "train", "info"));
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

        @Option(names = "--model", paramLabel = "<path>")
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
            out.println(Messages.text("model.trainingData", model.dataset()));
            out.println(Messages.text("model.datasetSize", model.datasetSize(), model.phishingExamples(),
                    model.legitimateExamples()));
            out.println(Messages.text("model.trainingAccuracy", percent(model.trainingAccuracy())));
        }
    }

    @Command(
            name = "train",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
    static final class TrainCommand extends ModelFileCommand {

        @Option(names = "--data", paramLabel = "<path>")
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
                err.println(Messages.text("model.error.loadData", source, describe(e)));
                return 1;
            }

            MlModel model = MlModel.train(data);
            Path file = modelFile();
            try {
                model.save(file);
            } catch (IOException | RuntimeException e) {
                err.println(Messages.text("model.error.save", file, describe(e)));
                return 1;
            }

            out.println(Messages.text("model.trained", algorithmName(model), model.featureCount()));
            printTrainingSummary(model);
            out.println(Messages.text("model.savedTo", file));
            return 0;
        }
    }

    @Command(
            name = "info",
            mixinStandardHelpOptions = true,
            versionProvider = Main.VersionProvider.class,
            sortOptions = false,
            descriptionHeading = "%n")
    static final class InfoCommand extends ModelFileCommand {

        InfoCommand(PrintStream out, PrintStream err) {
            super(out, err);
        }

        @Override
        public Integer call() {
            Path file = modelFile();
            if (!Files.exists(file)) {
                out.println(Messages.text("model.none", file));
                out.println(Messages.text("model.none.hint"));
                return 0;
            }
            MlModel model;
            try {
                model = MlModel.load(file);
            } catch (IOException | RuntimeException e) {
                err.println(Messages.text("model.error.read", file, describe(e)));
                err.println(Messages.text("model.retrainHint"));
                return 1;
            }

            out.println(Messages.text("model.file", file));
            out.println(Messages.text("model.algorithm", algorithmName(model)));
            out.println(Messages.text("model.trainedAt", model.trainedAt()));
            printTrainingSummary(model);
            out.println(Messages.text("model.features", model.featureCount()));
            double[] weights = model.classifier().weights();
            for (int i = 0; i < weights.length; i++) {
                out.println(String.format(Locale.ROOT, "  %-16s %+.3f", FeatureVector.NAMES.get(i), weights[i]));
            }
            out.println(String.format(Locale.ROOT, "  %-16s %+.3f", "(bias)", model.classifier().bias()));
            out.println(Messages.text("model.weightsHint"));
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
            return Messages.text("cli.fileNotFound");
        }
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }
}
