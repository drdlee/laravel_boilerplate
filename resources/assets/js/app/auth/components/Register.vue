<template>
  <div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">Register</div>

                <div class="panel-body">
                    <form class="form-horizontal"
                          @submit.prevent="submit">

                        <div class="form-group">
                            <label for="name" class="col-md-4 control-label">Name</label>

                            <div class="col-md-6">
                                <input
                                  id="name"
                                  type="text"
                                  class="form-control"
                                  name="name"
                                  v-model="name"
                                  required autofocus>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="email" class="col-md-4 control-label">E-Mail Address</label>

                            <div class="col-md-6">
                                <input
                                  id="email"
                                  type="email"
                                  class="form-control"
                                  name="email"
                                  v-model="email"
                                  required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="password" class="col-md-4 control-label">Password</label>

                            <div class="col-md-6">
                                <input
                                  id="password"
                                  type="password"
                                  class="form-control"
                                  name="password"
                                  v-model="password"
                                  required>
                            </div>
                        </div>

                        <div class="form-group">
                            <div class="col-md-6 col-md-offset-4">
                                <button type="submit" class="btn btn-primary">
                                    Register
                                </button>
                            </div>
                        </div>

                    </form>
                </div> <!-- panel-body -->
            </div> <!-- panel-default -->
        </div> <!-- column -->
    </div> <!-- row -->
</div><!-- container -->
</template>

<script>
import { mapActions } from 'vuex'
export default {
  data(){
    return {
      name: null,
      email: null,
      password: null
    }
  },
  methods: {
    ...mapActions({
      register: 'auth/register'
    }),
    submit(){
      this.register({
        payload: {
          name: this.name,
          email: this.email,
          password: this.password
        }
      })
    }
  }
}
</script>
