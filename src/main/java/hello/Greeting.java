package hello;

public class Greeting {

    private final String id;
    private final boolean attempt;
    private final String quote;

    public Greeting(String id, boolean attempt, String quote) {
        this.id = id;
        this.attempt = attempt;
        this.quote = quote;
    }

    public String getId() {
        return id;
    }
    
    public boolean getAttempt() {
        return attempt;
    }

    public String getQuote() {
        return quote;
    }
}

