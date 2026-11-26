-- Disable the API connection statement timeout for the following large
-- concurrent index rebuild migrations. SQLx applies these migrations in order.
SET statement_timeout = 0;
