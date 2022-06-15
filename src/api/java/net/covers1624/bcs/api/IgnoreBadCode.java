package net.covers1624.bcs.api;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Created by covers1624 on 13/6/22.
 */
@Retention (RetentionPolicy.RUNTIME)
@Target ({ ElementType.TYPE, ElementType.CONSTRUCTOR, ElementType.METHOD, ElementType.FIELD })
public @interface IgnoreBadCode {

    /**
     * Get the name of the group to ignore checks for.
     *
     * @return The group name.
     */
    String[] value();
}
